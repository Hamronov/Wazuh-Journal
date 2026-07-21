import { NextResponse } from "next/server";
import { currentSession, requireSession } from "@/lib/auth";
import { readAnalysisHistory } from "@/lib/analysis-history";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  if (!(await requireSession(request))) {
    return NextResponse.json(
      { error: "Требуется доменная авторизация Wazuh" },
      { status: 401 },
    );
  }
  const session = await currentSession(
    request.headers.get("cookie") || undefined,
  );
  const history = (await readAnalysisHistory()).filter(
    (item) => !session?.user || item.user === session.user,
  );
  return NextResponse.json(
    { history },
    { headers: { "cache-control": "no-store" } },
  );
}
