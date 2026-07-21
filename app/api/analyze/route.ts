import { NextResponse } from "next/server";

export async function POST(request: Request) {
  let alert: Record<string, unknown>;
  try {
    alert = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!alert?.id || !alert?.title) return NextResponse.json({ error: "Invalid alert" }, { status: 400 });

  const baseUrl = process.env.OPENAI_BASE_URL;
  const apiKey = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  if (!baseUrl || !apiKey) {
    return NextResponse.json({ demo: true, falsePositive: alert.falsePositive ?? 20 });
  }

  const compactAlert = {
    id: alert.id, level: alert.level, title: alert.title, host: alert.host,
    source_ip: alert.ip, rule_id: alert.rule, group: alert.group, summary: alert.detail,
  };
  const response = await fetch(`${baseUrl.replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model,
      temperature: 0.1,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: "Ты SOC-аналитик. Верни JSON: falsePositive (0-100), verdict, summary, ruleXml. Анализируй только переданный алерт. Не придумывай факты." },
        { role: "user", content: JSON.stringify(compactAlert) },
      ],
    }),
  });
  if (!response.ok) return NextResponse.json({ error: "AI provider error" }, { status: 502 });
  const data = await response.json() as { choices?: Array<{ message?: { content?: string } }> };
  const content = data.choices?.[0]?.message?.content;
  if (!content) return NextResponse.json({ error: "Empty AI response" }, { status: 502 });
  try {
    const parsed = JSON.parse(content) as Record<string, unknown>;
    const falsePositive = Number(parsed.falsePositive);
    return NextResponse.json({ ...parsed, falsePositive: Number.isFinite(falsePositive) ? Math.max(0, Math.min(100, falsePositive)) : 20 });
  } catch {
    return NextResponse.json({ error: "Invalid AI response" }, { status: 502 });
  }
}
