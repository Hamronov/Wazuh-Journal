import { NextResponse } from "next/server";
import { requireSession } from "@/lib/auth";
import { loadLocalSettings } from "@/lib/local-settings";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  if (!(await requireSession(request)))
    return NextResponse.json(
      { error: "Требуется доменная авторизация Wazuh" },
      { status: 401 },
    );
  try {
    await loadLocalSettings();
    const body = (await request.json()) as {
      baseUrl?: unknown;
      apiKey?: unknown;
    };
    const baseUrl = (
      typeof body.baseUrl === "string"
        ? body.baseUrl
        : process.env.OPENAI_BASE_URL || ""
    )
      .trim()
      .replace(/\/$/, "");
    const apiKey = (
      typeof body.apiKey === "string" && body.apiKey.trim()
        ? body.apiKey
        : process.env.OPENAI_API_KEY || ""
    ).trim();
    if (!baseUrl || !apiKey) throw new Error("Введите URL и API-ключ");
    const url = new URL(`${baseUrl}/models`);
    if (!["http:", "https:"].includes(url.protocol))
      throw new Error("Некорректный URL AI API");
    const response = await fetch(url, {
      headers: { authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(15000),
      cache: "no-store",
    });
    if (!response.ok)
      throw new Error(`Провайдер вернул HTTP ${response.status}`);
    const data = (await response.json()) as { data?: Array<{ id?: unknown }> };
    const models = (data.data || [])
      .map((item) => (typeof item.id === "string" ? item.id : ""))
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b));
    if (!models.length) throw new Error("Провайдер не вернул доступные модели");
    return NextResponse.json({ models });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error ? error.message : "Не удалось получить модели",
      },
      { status: 400 },
    );
  }
}
