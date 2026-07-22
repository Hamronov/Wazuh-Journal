import { NextResponse } from "next/server";
import { loadLocalSettings } from "@/lib/local-settings";
import { requireSession } from "@/lib/auth";
import { appendAnalysis, updateAnalysis } from "@/lib/analysis-history";
import { runWazuhCommand } from "@/lib/wazuh";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const rulesPath = "/var/ossec/etc/rules/local_rules.xml";

export async function POST(request: Request) {
  const session = await requireSession(request);
  if (!session)
    return NextResponse.json(
      { error: "Требуется доменная авторизация Wazuh" },
      { status: 401 },
    );
  await loadLocalSettings();
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const alerts = Array.isArray(payload)
    ? payload
    : payload &&
        typeof payload === "object" &&
        Array.isArray((payload as { alerts?: unknown }).alerts)
      ? (payload as { alerts: unknown[] }).alerts
      : [payload];
  const validAlerts = alerts
    .filter((item): item is Record<string, unknown> =>
      Boolean(
        item &&
        typeof item === "object" &&
        (item as Record<string, unknown>).id &&
        (item as Record<string, unknown>).title,
      ),
    )
    .slice(0, 5);
  if (!validAlerts.length)
    return NextResponse.json({ error: "Invalid alert" }, { status: 400 });

  const baseUrl = process.env.OPENAI_BASE_URL;
  const apiKey = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  if (!baseUrl || !apiKey) {
    return NextResponse.json({ error: "AI API не настроен" }, { status: 503 });
  }

  const compactAlerts = validAlerts.map((alert) => ({
    id: String(alert.id),
    level: Number(alert.level) || 0,
    title: String(alert.title),
    host: String(alert.host || ""),
    source_ip: String(alert.ip || ""),
    rule_id: String(alert.rule || ""),
    group: String(alert.group || ""),
    summary: String(alert.story || alert.detail || "").slice(0, 700),
    fields: Array.isArray(alert.fields) ? alert.fields.slice(0, 8) : [],
  }));
  const stored = await appendAnalysis({
    user: session.user,
    alert: validAlerts.length === 1 ? validAlerts[0] : { alerts: validAlerts },
    analysis: { status: "processing", verdict: "В обработке", summary: "Запрос отправлен в AI API.", falsePositive: 0, ruleXml: "" },
  });
  const fail = async (message: string, status: number) => {
    await updateAnalysis(stored.id, { analysis: { status: "error", verdict: "Ошибка", summary: message, falsePositive: 0, ruleXml: "" } });
    return NextResponse.json({ error: message, historyId: stored.id }, { status });
  };
  let existingRules: string;
  try {
    existingRules = await runWazuhCommand(
      `sudo -S -p '' su -c 'cat ${rulesPath}'`,
    );
  } catch (error) {
    return fail(
      error instanceof Error
        ? `Не удалось прочитать действующие правила Wazuh: ${error.message}`
        : "Не удалось прочитать действующие правила Wazuh",
      503,
    );
  }
  let response: Response;
  try {
    response = await fetch(`${baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 900,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content:
              "Ты SOC-аналитик. Проанализируй один или несколько алертов как единый инцидент и обязательно сопоставь их с existingRules — актуальным local_rules.xml. Сначала проверь, есть ли уже узкое исключение level 0, которое должно было подавить эти алерты. Если оно есть, объясни в exceptionExplanation, почему оно не сработало: какое условие, поле, значение, if_sid/if_group или порядок правил не совпали с алертом. Затем верни в ruleXml исправленную полную версию именно этого <rule> с тем же id. Не меняй обычное детектирующее правило: изменять можно только явно подходящее исключение level 0. Если подходящего исключения нет и это ложное срабатывание, предложи одно новое узкое черновое Wazuh XML-правило level 0; для нового правила id не указывай. Не расширяй исключение больше необходимого. Верни компактный JSON только с полями falsePositive (0-100), verdict, summary, exceptionExplanation, ruleXml. Если правило не нужно, ruleXml пустой. Не придумывай отсутствующие поля или факты.",
          },
          {
            role: "user",
            content: JSON.stringify({ alerts: compactAlerts, existingRules }),
          },
        ],
        signal: AbortSignal.timeout(25000),
      }),
    });
  } catch (error) {
    const timedOut =
      error instanceof Error &&
      (error.name === "TimeoutError" || error.name === "AbortError");
    return fail(timedOut ? "AI не ответил за 25 секунд" : "AI API недоступен", 504);
  }
  if (!response.ok)
    return fail(`AI provider error (HTTP ${response.status})`, 502);
  const data = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const message = data.choices?.[0]?.message as
    { content?: unknown; reasoning_content?: unknown } | undefined;
  const rawContent = message?.content ?? message?.reasoning_content;
  const content = Array.isArray(rawContent)
    ? rawContent
        .map((part) =>
          typeof part === "string"
            ? part
            : part && typeof part === "object" && "text" in part
              ? String((part as { text?: unknown }).text || "")
              : "",
        )
        .join("")
    : typeof rawContent === "string"
      ? rawContent
      : "";
  if (!content)
    return fail("AI вернул пустой ответ. Проверьте выбранную модель и формат JSON.", 502);
  try {
    const normalizedContent = content
      .replace(/^```(?:json)?\s*/i, "")
      .replace(/\s*```$/i, "")
      .trim();
    const parsed = JSON.parse(normalizedContent) as Record<string, unknown>;
    // Некоторые OpenAI-совместимые модели возвращают булево значение
    // для falsePositive и null для пустого ruleXml, несмотря на инструкцию
    // схемы. Нормализуем эти безопасные варианты перед валидацией.
    const falsePositive =
      typeof parsed.falsePositive === "boolean"
        ? parsed.falsePositive
          ? 100
          : 0
        : Number(parsed.falsePositive);
    if (
      !Number.isFinite(falsePositive) ||
      typeof parsed.verdict !== "string" ||
      typeof parsed.summary !== "string" ||
      !(typeof parsed.ruleXml === "string" || parsed.ruleXml === null)
    )
      throw new Error("Invalid schema");
    const result = {
      ...parsed,
      falsePositive: Math.max(0, Math.min(100, falsePositive)),
      ruleXml: typeof parsed.ruleXml === "string" ? parsed.ruleXml : "",
      exceptionExplanation:
        typeof parsed.exceptionExplanation === "string"
          ? parsed.exceptionExplanation
          : "",
    };
    await updateAnalysis(stored.id, { analysis: { ...result, status: "success" } });
    return NextResponse.json({
      ...result,
      historyId: stored.id,
      analyzedAt: stored.analyzedAt,
    });
  } catch {
    return NextResponse.json({ error: "Invalid AI response" }, { status: 502 });
  }
}
