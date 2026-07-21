import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type StoredAnalysis = {
  id: string;
  analyzedAt: string;
  user: string;
  alert: Record<string, unknown>;
  analysis: Record<string, unknown>;
};

const historyPath = join(process.cwd(), ".analysis-history.json");

export async function readAnalysisHistory(): Promise<StoredAnalysis[]> {
  try {
    const parsed = JSON.parse(await readFile(historyPath, "utf8"));
    return Array.isArray(parsed) ? (parsed as StoredAnalysis[]) : [];
  } catch {
    return [];
  }
}

export async function appendAnalysis(
  entry: Omit<StoredAnalysis, "id" | "analyzedAt">,
) {
  const history = await readAnalysisHistory();
  const item: StoredAnalysis = {
    ...entry,
    id: crypto.randomUUID(),
    analyzedAt: new Date().toISOString(),
  };
  const next = [item, ...history].slice(0, 500);
  const temporary = `${historyPath}.tmp`;
  await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporary, historyPath);
  return item;
}

export async function updateAnalysis(
  id: string,
  patch: Partial<Pick<StoredAnalysis, "analysis" | "analyzedAt">>,
) {
  const history = await readAnalysisHistory();
  const index = history.findIndex((item) => item.id === id);
  if (index < 0) return null;
  history[index] = {
    ...history[index],
    ...patch,
    analysis: patch.analysis
      ? { ...history[index].analysis, ...patch.analysis }
      : history[index].analysis,
  };
  const temporary = `${historyPath}.tmp`;
  await writeFile(temporary, `${JSON.stringify(history, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporary, historyPath);
  return history[index];
}
