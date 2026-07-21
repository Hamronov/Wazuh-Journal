import { NextResponse } from "next/server";
import { loadWazuhAlerts } from "@/lib/wazuh";
import { loadLocalSettings } from "@/lib/local-settings";
import { requireSession } from "@/lib/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  if (!(await requireSession(request))) {
    return NextResponse.json(
      { error: "Требуется доменная авторизация Wazuh" },
      { status: 401 },
    );
  }

  await loadLocalSettings();
  const wazuh = await loadWazuhAlerts()
    .then(() => ({ ok: true }))
    .catch((error) => ({
      ok: false,
      error: error instanceof Error ? error.message : "Ошибка Wazuh",
    }));
  const aiConfigured = Boolean(
    process.env.OPENAI_BASE_URL &&
    process.env.OPENAI_API_KEY &&
    process.env.OPENAI_MODEL,
  );

  return NextResponse.json(
    {
      wazuh,
      ai: {
        ok: aiConfigured,
        error: aiConfigured ? undefined : "AI API не настроен",
      },
    },
    { headers: { "cache-control": "no-store" } },
  );
}
