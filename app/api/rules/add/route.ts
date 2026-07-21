import { NextResponse } from "next/server";
import { runWazuhCommand } from "@/lib/wazuh";
import { requireSession } from "@/lib/auth";
import { updateAnalysis } from "@/lib/analysis-history";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const path = "/var/ossec/etc/rules/local_rules.xml";

function nextRuleId(xml: string) {
  const ids = [...xml.matchAll(/<rule\b[^>]*\bid\s*=\s*["'](\d+)["']/gi)]
    .map((match) => Number(match[1]))
    .filter(Number.isFinite);
  let candidate = Math.max(100000, ...ids) + 1;
  const used = new Set(ids);
  while (used.has(candidate)) candidate += 1;
  if (candidate > 999999)
    throw new Error("Не найден свободный номер правила в диапазоне Wazuh");
  return candidate;
}

function prepareRule(ruleXml: string, id: number) {
  const match = ruleXml.match(/<rule\b[^>]*>([\s\S]*?)<\/rule>/i);
  if (!match) throw new Error("AI не вернул корректное XML-правило");
  const body = match[1].trim();
  if (!body || /<group\b/i.test(body) || /<rule\b/i.test(body))
    throw new Error("XML-правило содержит недопустимую вложенную структуру");
  if (!/<description\b/i.test(body))
    throw new Error("У правила отсутствует description");
  return `<rule id="${id}" level="0">\n${body}\n</rule>`;
}

export async function POST(request: Request) {
  if (!(await requireSession(request)))
    return NextResponse.json(
      { error: "Требуется доменная авторизация Wazuh" },
      { status: 401 },
    );
  try {
    const body = (await request.json()) as {
      ruleXml?: unknown;
      historyId?: unknown;
    };
    if (typeof body.ruleXml !== "string" || !body.ruleXml.trim())
      throw new Error("Пустое XML-правило");
    const existing = await runWazuhCommand(`sudo -S -p '' su -c 'cat ${path}'`);
    const id = nextRuleId(existing);
    const rule = prepareRule(body.ruleXml, id);
    const group = /<group\s+name=["']ai_suppressions,["'][^>]*>/i;
    const next = group.test(existing)
      ? existing.replace(
          /(<group\s+name=["']ai_suppressions,["'][^>]*>[\s\S]*?)(<\/group>)/i,
          `$1\n  ${rule.replace(/\n/g, "\n  ")}\n$2`,
        )
      : `${existing.trim()}\n\n<group name="ai_suppressions,">\n  ${rule.replace(/\n/g, "\n  ")}\n</group>\n`;
    const encoded = Buffer.from(next, "utf8").toString("base64");
    await runWazuhCommand(
      `sudo -S -p '' su -c 'cp ${path} ${path}.bak && printf %s ${encoded} | base64 -d > ${path}.tmp && chown root:wazuh ${path}.tmp && chmod 660 ${path}.tmp && mv ${path}.tmp ${path} && systemctl restart wazuh-manager'`,
    );
    if (typeof body.historyId === "string") {
      await updateAnalysis(body.historyId, {
        analysis: {
          ruleAdded: true,
          ruleId: id,
        },
      });
    }
    return NextResponse.json({
      ok: true,
      id,
      group: "ai_suppressions",
      level: 0,
      historyId:
        typeof body.historyId === "string" ? body.historyId : undefined,
    });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Не удалось добавить правило",
      },
      { status: 400 },
    );
  }
}
