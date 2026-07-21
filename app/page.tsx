"use client";
/* eslint-disable @typescript-eslint/no-unused-vars, react-hooks/set-state-in-effect */
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

type Alert = {
  id: string;
  time: string;
  timestamp: string;
  level: number;
  title: string;
  host: string;
  ip: string;
  rule: string;
  group: string;
  detail: string;
  story?: string;
  fields?: [string, string][];
};
type Analysis = {
  status?: "processing" | "error" | "success";
  ruleAdded?: boolean;
  ruleId?: number;
  falsePositive: number;
  verdict: string;
  summary: string;
  exceptionExplanation?: string;
  ruleXml: string;
  historyId?: string;
  analyzedAt?: string;
};
type AnalysisHistoryItem = {
  id: string;
  analyzedAt: string;
  user: string;
  alert: Record<string, unknown> | { alerts: Record<string, unknown>[] };
  analysis: Analysis;
};
type Health = { ok: boolean; error?: string };
type Settings = Record<string, string | boolean>;
function Level({ value }: { value: number }) {
  return (
    <span
      className={`level l${value >= 10 ? "high" : value >= 7 ? "med" : "low"}`}
    >
      L{value}
    </span>
  );
}
function batchDate(timestamp: string) {
  const date = new Date(timestamp),
    pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())} ${pad(date.getDate())}.${pad(date.getMonth() + 1)}.${String(date.getFullYear()).slice(-2)}`;
}
function batchClock(timestamp: string) {
  const date = new Date(timestamp),
    pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function batchDay(timestamp: string) {
  const date = new Date(timestamp),
    pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getDate())}.${pad(date.getMonth() + 1)}.${String(date.getFullYear()).slice(-2)}`;
}

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([]),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [updated, setUpdated] = useState(""),
    [hasMore, setHasMore] = useState(false),
    [nextCursor, setNextCursor] = useState<string | null>(null),
    [loadingMore, setLoadingMore] = useState(false);
  const [selected, setSelected] = useState<Alert | null>(null),
    [selectedAnalysisCount, setSelectedAnalysisCount] = useState(1),
    [analysis, setAnalysis] = useState<Analysis | null>(null),
    [analysisError, setAnalysisError] = useState(""),
    [analyzing, setAnalyzing] = useState(false),
    [filter, setFilter] = useState<
      "all" | "8to10" | "10to12" | "12to15" | "marked" | "skipped"
    >("all");
  const [tab, setTab] = useState<"feed" | "rules">("feed"),
    [expanded, setExpanded] = useState<string | null>(null),
    [marked, setMarked] = useState<Set<string>>(new Set()),
    [skipped, setSkipped] = useState<Set<string>>(new Set()),
    [period, setPeriod] = useState<"all" | "today" | "hour" | "range">("all"),
    [dateFrom, setDateFrom] = useState(""),
    [dateTo, setDateTo] = useState(""),
    [batchPage, setBatchPage] = useState(0);
  useEffect(() => {
    try {
      setMarked(
        new Set(JSON.parse(localStorage.getItem("wazuh-marked") || "[]")),
      );
      setSkipped(
        new Set(JSON.parse(localStorage.getItem("wazuh-skipped") || "[]")),
      );
    } catch {}
  }, []);
  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("wazuh-ui-state") || "{}");
      if (saved.tab === "feed" || saved.tab === "rules") setTab(saved.tab);
      if (
        ["all", "8to10", "10to12", "12to15", "marked", "skipped"].includes(
          saved.filter,
        )
      )
        setFilter(saved.filter);
      if (["all", "today", "hour", "range"].includes(saved.period))
        setPeriod(saved.period);
      if (typeof saved.dateFrom === "string") setDateFrom(saved.dateFrom);
      if (typeof saved.dateTo === "string") setDateTo(saved.dateTo);
    } catch {}
  }, []);
  useEffect(() => {
    localStorage.setItem(
      "wazuh-ui-state",
      JSON.stringify({ tab, filter, period, dateFrom, dateTo }),
    );
  }, [tab, filter, period, dateFrom, dateTo]);
  useEffect(() => {
    localStorage.setItem("wazuh-marked", JSON.stringify([...marked]));
  }, [marked]);
  useEffect(() => {
    localStorage.setItem("wazuh-skipped", JSON.stringify([...skipped]));
  }, [skipped]);
  const [settingsOpen, setSettingsOpen] = useState(false),
    [checking, setChecking] = useState(false),
    [sessionUser, setSessionUser] = useState(""),
    [authReady, setAuthReady] = useState(false);
  const [analysisHistory, setAnalysisHistory] = useState<AnalysisHistoryItem[]>(
      [],
    ),
    [historyOpen, setHistoryOpen] = useState(false),
    [unreadAnalysisIds, setUnreadAnalysisIds] = useState<Set<string>>(() => {
      if (typeof window === "undefined") return new Set();
      try {
        return new Set(
          JSON.parse(localStorage.getItem("wazuh-analysis-unread") || "[]"),
        );
      } catch {
        return new Set();
      }
    }),
    [analyzedIds, setAnalyzedIds] = useState<Set<string>>(new Set()),
    [ruleAddState, setRuleAddState] = useState<"idle" | "adding" | "added">(
      "idle",
    ),
    [ruleAddError, setRuleAddError] = useState("");
  const [settings, setSettings] = useState<Settings>({}),
    [saving, setSaving] = useState(false),
    [saveMessage, setSaveMessage] = useState(""),
    [aiModels, setAiModels] = useState<string[]>([]),
    [modelsLoading, setModelsLoading] = useState(false);
  const [ruleNotice, setRuleNotice] = useState("");
  const [health, setHealth] = useState<Record<string, Health>>({
    wazuh: { ok: false },
    ai: { ok: false },
  });
  useEffect(() => {
    localStorage.setItem(
      "wazuh-analysis-unread",
      JSON.stringify([...unreadAnalysisIds]),
    );
  }, [unreadAnalysisIds]);
  useEffect(() => {
    fetch("/api/auth/session", { cache: "no-store" })
      .then((response) => response.json())
      .then((data) => {
        if (data.authenticated) setSessionUser(String(data.user || ""));
        setAuthReady(true);
      })
      .catch(() => setAuthReady(true));
  }, []);
  const loadAnalysisHistory = useCallback(async () => {
    try {
      const response = await fetch("/api/analysis-history", {
        cache: "no-store",
      });
      if (!response.ok) return;
      const data = (await response.json()) as {
        history?: AnalysisHistoryItem[];
      };
      const items = data.history || [];
      setAnalysisHistory(items);
      setAnalyzedIds(
        new Set(
          items
            .flatMap((item) =>
              "alerts" in item.alert ? item.alert.alerts : [item.alert],
            )
            .map((alert) => String((alert as Record<string, unknown>).id || ""))
            .filter(Boolean),
        ),
      );
    } catch {}
  }, []);
  const loadInFlight = useRef(false);
  const expandedRef = useRef<string | null>(null);
  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);
  const load = useCallback(async () => {
    if (loadInFlight.current) return;
    loadInFlight.current = true;
    const expandedId = expandedRef.current,
      anchor = expandedId
        ? document.querySelector(
            `[data-expanded-anchor="${CSS.escape(expandedId)}"]`,
          )
        : null,
      top = anchor?.getBoundingClientRect().top;
    try {
      const params = new URLSearchParams({ limit: "500" }),
        nowDate = new Date();
      if (filter === "8to10") params.set("maxLevel", "9");
      if (filter === "10to12") {
        params.set("minLevel", "10");
        params.set("maxLevel", "11");
      }
      if (filter === "12to15") {
        params.set("minLevel", "12");
        params.set("maxLevel", "15");
      }
      if (period === "hour")
        params.set("from", new Date(nowDate.getTime() - 3600000).toISOString());
      if (period === "today")
        params.set(
          "from",
          new Date(
            nowDate.getFullYear(),
            nowDate.getMonth(),
            nowDate.getDate(),
          ).toISOString(),
        );
      if (period === "range" && dateFrom)
        params.set("from", new Date(`${dateFrom}T00:00:00`).toISOString());
      if (period === "range" && dateTo)
        params.set("to", new Date(`${dateTo}T23:59:59`).toISOString());
      const r = await fetch(`/api/alerts?${params}`, { cache: "no-store" }),
        data = await r.json();
      if (!r.ok) throw new Error(data.error || "Wazuh недоступен");
      setAlerts(
        (data.alerts || []).sort((a: Alert, b: Alert) =>
          b.timestamp.localeCompare(a.timestamp),
        ),
      );
      setHasMore(Boolean(data.hasMore));
      setNextCursor(data.nextCursor || null);
      setUpdated(data.updatedAt);
      setError("");
      if (anchor && top !== undefined)
        requestAnimationFrame(() => {
          const next = document.querySelector(
            `[data-expanded-anchor="${CSS.escape(expandedId || "")}"]`,
          );
          if (next)
            window.scrollBy({ top: next.getBoundingClientRect().top - top });
        });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка загрузки");
    } finally {
      loadInFlight.current = false;
      setLoading(false);
    }
  }, [period, dateFrom, dateTo, filter]);
  const loadMore = async () => {
    if (loadingMore || !hasMore || !nextCursor) return;
    setLoadingMore(true);
    try {
      const params = new URLSearchParams({ limit: "500", cursor: nextCursor }),
        nowDate = new Date();
      if (filter === "8to10") params.set("maxLevel", "9");
      if (filter === "10to12") {
        params.set("minLevel", "10");
        params.set("maxLevel", "11");
      }
      if (filter === "12to15") {
        params.set("minLevel", "12");
        params.set("maxLevel", "15");
      }
      if (period === "hour")
        params.set("from", new Date(nowDate.getTime() - 3600000).toISOString());
      if (period === "today")
        params.set(
          "from",
          new Date(
            nowDate.getFullYear(),
            nowDate.getMonth(),
            nowDate.getDate(),
          ).toISOString(),
        );
      if (period === "range" && dateFrom)
        params.set("from", new Date(`${dateFrom}T00:00:00`).toISOString());
      if (period === "range" && dateTo)
        params.set("to", new Date(`${dateTo}T23:59:59`).toISOString());
      const response = await fetch(`/api/alerts?${params}`, {
          cache: "no-store",
        }),
        data = await response.json();
      if (!response.ok) throw new Error(data.error);
      setAlerts((current) => [...current, ...data.alerts]);
      setHasMore(Boolean(data.hasMore));
      setNextCursor(data.nextCursor || null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка архива");
    } finally {
      setLoadingMore(false);
    }
  };
  const checkIntegrations = useCallback(async () => {
    setChecking(true);
    try {
      const response = await fetch("/api/integrations", { cache: "no-store" });
      setHealth(await response.json());
    } finally {
      setChecking(false);
    }
  }, []);
  const openSettings = async () => {
    setSettingsOpen(true);
    setSaveMessage("");
    const response = await fetch("/api/settings", { cache: "no-store" });
    setSettings(await response.json());
  };
  const saveSettings = async () => {
    setSaving(true);
    setSaveMessage("");
    try {
      const response = await fetch("/api/settings", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(settings),
        }),
        data = await response.json();
      if (!response.ok) throw new Error(data.error || "Ошибка сохранения");
      setSaveMessage("Настройки сохранены");
      await checkIntegrations();
      await load();
    } catch (error) {
      setSaveMessage(
        error instanceof Error ? error.message : "Ошибка сохранения",
      );
    } finally {
      setSaving(false);
    }
  };
  const setSetting = (key: string, value: string) =>
    setSettings((current) => ({ ...current, [key]: value }));
  const requestModels = async () => {
    setModelsLoading(true);
    setSaveMessage("");
    try {
      const response = await fetch("/api/ai/models", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            baseUrl: settings.OPENAI_BASE_URL,
            apiKey: settings.OPENAI_API_KEY,
          }),
        }),
        data = await response.json();
      if (!response.ok)
        throw new Error(data.error || "Не удалось получить модели");
      setAiModels(data.models || []);
      if (!settings.OPENAI_MODEL && data.models?.[0])
        setSetting("OPENAI_MODEL", data.models[0]);
      setSaveMessage(`Получено моделей: ${data.models?.length || 0}`);
    } catch (error) {
      setSaveMessage(
        error instanceof Error ? error.message : "Ошибка получения моделей",
      );
    } finally {
      setModelsLoading(false);
    }
  };
  useEffect(() => {
    if (!authReady || !sessionUser) return;
    queueMicrotask(async () => {
      await load();
      await checkIntegrations();
    });
    const timer = setInterval(load, 30000);
    return () => clearInterval(timer);
  }, [authReady, sessionUser, load, checkIntegrations]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSettingsOpen(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, []);
  const visible = useMemo(
    () =>
      alerts.filter((a) => {
        const time = new Date(a.timestamp).getTime(),
          day = new Date(a.timestamp).toISOString().slice(0, 10),
          now = updated ? new Date(updated).getTime() : 0,
          level =
            filter === "all" ||
            (filter === "8to10" && a.level >= 8 && a.level < 10) ||
            (filter === "10to12" && a.level >= 10 && a.level < 12) ||
            (filter === "12to15" && a.level >= 12 && a.level <= 15) ||
            (filter === "marked" && marked.has(a.id)) ||
            (filter === "skipped" && skipped.has(a.id));
        const dates =
          period === "all" ||
          (period === "today" &&
            day ===
              (updated ? new Date(updated).toISOString().slice(0, 10) : day)) ||
          (period === "hour" && now - time <= 3600000) ||
          (period === "range" &&
            (!dateFrom || day >= dateFrom) &&
            (!dateTo || day <= dateTo));
        return level && dates;
      }),
    [alerts, filter, marked, skipped, period, dateFrom, dateTo, updated],
  );
  const batches = useMemo(() => {
    const ordered = [...visible].sort((a, b) =>
        b.timestamp.localeCompare(a.timestamp),
      ),
      result: Alert[][] = [];
    for (let i = 0; i < ordered.length; i += 5)
      result.push(ordered.slice(i, i + 5));
    return result;
  }, [visible]);
  const batchPageCount = Math.max(1, Math.ceil(batches.length / 50)),
    pageBatches = batches.slice(batchPage * 50, (batchPage + 1) * 50);
  useEffect(() => {
    setBatchPage(0);
  }, [period, dateFrom, dateTo, filter]);
  const analyze = async (input: Alert | Alert[]) => {
    const alertsToAnalyze = Array.isArray(input) ? input : [input];
    setSelected(alertsToAnalyze[0]);
    setSelectedAnalysisCount(alertsToAnalyze.length);
    setAnalysis(null);
    setAnalysisError("");
    setRuleAddState("idle");
    setRuleAddError("");
    setAnalyzing(true);
    try {
      const r = await fetch("/api/analyze", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ alerts: alertsToAnalyze }),
        }),
        data = await r.json();
      if (!r.ok) throw new Error(data.error || "AI недоступен");
      setAnalysis(data);
      setAnalyzedIds(
        (current) =>
          new Set([...current, ...alertsToAnalyze.map((alert) => alert.id)]),
      );
      await loadAnalysisHistory();
    } catch (e) {
      setAnalysisError(e instanceof Error ? e.message : "Ошибка анализа");
    } finally {
      setAnalyzing(false);
    }
  };
  const addRule = async () => {
    if (!analysis?.ruleXml || ruleAddState === "adding") return;
    setRuleAddState("adding");
    setRuleAddError("");
    try {
      const response = await fetch("/api/rules/add", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ruleXml: analysis.ruleXml,
          historyId: analysis.historyId,
        }),
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(data.error || "Не удалось добавить правило");
      setRuleAddState("added");
      setRuleNotice("Правило добавлено, Wazuh Manager перезапущен");
      await loadAnalysisHistory();
      window.setTimeout(() => setRuleNotice(""), 5000);
    } catch (error) {
      setRuleAddState("idle");
      setRuleAddError(
        error instanceof Error ? error.message : "Ошибка добавления правила",
      );
      setRuleNotice("Не удалось добавить правило");
      window.setTimeout(() => setRuleNotice(""), 5000);
    }
  };
  useEffect(() => {
    if (authReady && sessionUser) void loadAnalysisHistory();
  }, [authReady, sessionUser, loadAnalysisHistory]);
  if (!authReady) return <AuthLoading />;
  if (!sessionUser) return <Login onLogin={setSessionUser} />;
  return (
    <main>
      {ruleNotice && <div className="rule-toast" role="status">{ruleNotice}</div>}
      <header className="topbar">
        <div className="brand">
          <span className="brandmark">W</span>
          <span>
            Wazuh
            <br />
            Journal
          </span>
        </div>
        <nav>
          <button
            className={tab === "feed" ? "nav-active" : ""}
            onClick={() => setTab("feed")}
          >
            Лента
          </button>
          <button
            className={tab === "rules" ? "nav-active" : ""}
            onClick={() => setTab("rules")}
          >
            Правила
          </button>
          <button
            className={historyOpen ? "nav-active" : ""}
            onClick={() => setHistoryOpen(true)}
          >
            Анализы
            {analysisHistory.length ? ` · ${analysisHistory.length}` : ""}
            {unreadAnalysisIds.size ? ` · новые ${unreadAnalysisIds.size}` : ""}
          </button>
          <button onClick={openSettings}>Настройки</button>
        </nav>
        <div className="user">
          <span className={`status-dot ${health.wazuh.ok ? "" : "offline"}`} />
          <span>
            <b>{sessionUser}</b>
            <small>SECURITY CONSOLE</small>
          </span>
          <button
            className="avatar avatar-button"
            onClick={openSettings}
            aria-label="Открыть настройки"
          >
            SOC
          </button>
        </div>
      </header>
      <section className="status-strip">
        <div>
          <small>WAZUH</small>
          <b className={health.wazuh.ok ? "ok" : "bad"}>
            {health.wazuh.ok ? "ПОДКЛЮЧЕН" : "НЕДОСТУПЕН"}
          </b>
        </div>
        <div>
          <small>AI API</small>
          <b className={health.ai.ok ? "ok" : "bad"}>
            {health.ai.ok ? "НАСТРОЕН" : "НЕ НАСТРОЕН"}
          </b>
        </div>
        <button onClick={load} disabled={loading}>
          {loading ? "ОБНОВЛЕНИЕ…" : "ОБНОВИТЬ"}
        </button>
      </section>
      <section className="workspace workspace-top">
        {tab === "rules" ? (
          <RuleConstructorV2 />
        ) : (
          <>
            <div className="toolbar">
              <div className="date">
                <span>
                  <small>ЛОКАЛЬНАЯ ЛЕНТА</small>
                  {updated
                    ? new Date(updated).toLocaleString("ru-RU")
                    : "Нет синхронизации"}
                </span>
              </div>
              <div className="filter-groups">
                <div className="filters level-filters">
                  <button
                    className={filter === "all" ? "filter-primary" : ""}
                    onClick={() => setFilter("all")}
                  >
                    Все
                  </button>
                  <button
                    className={filter === "8to10" ? "filter-primary" : ""}
                    onClick={() => setFilter("8to10")}
                  >
                    L8–10
                  </button>
                  <button
                    className={filter === "10to12" ? "filter-primary" : ""}
                    onClick={() => setFilter("10to12")}
                  >
                    L10–12
                  </button>
                  <button
                    className={filter === "12to15" ? "filter-primary" : ""}
                    onClick={() => setFilter("12to15")}
                  >
                    L12–15
                  </button>
                  <button
                    className={filter === "marked" ? "filter-primary" : ""}
                    onClick={() => setFilter("marked")}
                  >
                    Помеченные
                  </button>
                  <button
                    className={filter === "skipped" ? "filter-primary" : ""}
                    onClick={() => setFilter("skipped")}
                  >
                    Пропущенные
                  </button>
                </div>
                <div className="filters time-filters">
                  <button
                    className={period === "all" ? "filter-primary" : ""}
                    onClick={() => setPeriod("all")}
                  >
                    За всё время
                  </button>
                  <button
                    className={period === "hour" ? "filter-primary" : ""}
                    onClick={() => setPeriod("hour")}
                  >
                    За последний час
                  </button>
                  <button
                    className={period === "today" ? "filter-primary" : ""}
                    onClick={() => setPeriod("today")}
                  >
                    За сегодня
                  </button>
                  <button
                    className={period === "range" ? "filter-primary" : ""}
                    onClick={() => setPeriod("range")}
                  >
                    За период
                  </button>
                  {period === "range" && (
                    <span className="period-controls">
                      <input
                        type="date"
                        value={dateFrom}
                        onChange={(event) => setDateFrom(event.target.value)}
                      />
                      <input
                        type="date"
                        value={dateTo}
                        onChange={(event) => setDateTo(event.target.value)}
                      />
                    </span>
                  )}
                </div>
              </div>
            </div>
            <Feed
              error={error}
              loading={loading}
              batches={pageBatches}
              expanded={expanded}
              setExpanded={setExpanded}
              analyze={analyze}
              load={load}
              marked={marked}
              skipped={skipped}
              setMarked={setMarked}
              setSkipped={setSkipped}
              analyzedIds={analyzedIds}
            />
            {batchPageCount > 1 && (
              <BatchPager
                page={batchPage}
                pages={batchPageCount}
                onChange={setBatchPage}
              />
            )}{" "}
            {hasMore && (
              <button
                className="archive-more"
                onClick={loadMore}
                disabled={loadingMore}
              >
                {loadingMore ? "ЗАГРУЖАЮ…" : "ЗАГРУЗИТЬ ЕЩЁ 500 АЛЕРТОВ"}
              </button>
            )}
          </>
        )}
      </section>
      <footer>
        <span>WAZUH JOURNAL / LOCAL</span>
        <span>
          <i className={`status-dot ${health.wazuh.ok ? "" : "offline"}`} /> SSH
          · {health.wazuh.ok ? "ПОДКЛЮЧЕНО" : "НЕТ СВЯЗИ"}
        </span>
        <span>ОБНОВЛЕНИЕ КАЖДЫЕ 30 СЕК</span>
      </footer>
      {selected && (
        <div className="modal-backdrop" onMouseDown={() => setSelected(null)}>
          <aside
            className="analysis-panel"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <div className="panel-top">
              <button className="analysis-back" onClick={() => { setSelected(null); setHistoryOpen(true); }} aria-label="Назад к истории">←</button>
              <span className="ai-badge">✦ AI АНАЛИЗ</span>
              <button onClick={() => setSelected(null)}>×</button>
            </div>
            <div className="panel-heading">
              <Level value={selected.level} />
              <h2>
                {selectedAnalysisCount > 1
                  ? `Пачка · ${selectedAnalysisCount} алертов`
                  : selected.title}
              </h2>
              <p>
                {selected.host} · {selected.time} · RULE {selected.rule}
              </p>
            </div>
            {analyzing ? (
              <div className="loading">
                <div className="orb">✦</div>
                <h3>Анализирую сигнал</h3>
                <p>
                  {selectedAnalysisCount > 1
                    ? `В AI API отправлена пачка из ${selectedAnalysisCount} алертов.`
                    : "В AI API отправлен только выбранный алерт."}
                </p>
              </div>
            ) : analysisError ? (
              <div className="connection-error">
                <h3>Анализ недоступен</h3>
                <p>{analysisError}</p>
              </div>
            ) : (
              analysis && (
                <div className="result">
                  <section className="verdict">
                    <div>
                      <small>ШАНС ЛОЖНОГО СРАБАТЫВАНИЯ</small>
                      <strong>{analysis.falsePositive}%</strong>
                    </div>
                    <div className="meter">
                      <i style={{ width: `${analysis.falsePositive}%` }} />
                    </div>
                    <p>{analysis.verdict}</p>
                  </section>
                  <section>
                    <small>КРАТКИЙ ВЫВОД</small>
                    <p>{analysis.summary}</p>
                  </section>
                  {analysis.exceptionExplanation && (
                    <section className="exception-explanation">
                      <small>КАК РАБОТАЕТ ИСКЛЮЧЕНИЕ</small>
                      <p>{analysis.exceptionExplanation}</p>
                    </section>
                  )}
                  <section className="rule-box">
                    <div className="rule-label">
                      <span>ЧЕРНОВИК ПРАВИЛА</span>
                      <span>XML</span>
                    </div>
                    <code>{analysis.ruleXml}</code>
                  </section>
                  {analysis.ruleXml && (
                    <div className="rule-add-area">
                      <button
                        className="check-button"
                        onClick={addRule}
                        disabled={
                          ruleAddState === "adding" || ruleAddState === "added"
                        }
                      >
                        {ruleAddState === "adding"
                          ? "ДОБАВЛЯЮ И ПЕРЕЗАПУСКАЮ…"
                          : ruleAddState === "added"
                            ? "ПРАВИЛО ДОБАВЛЕНО · MANAGER ПЕРЕЗАПУЩЕН"
                            : "ДОБАВИТЬ ПРАВИЛО И ПЕРЕЗАПУСТИТЬ"}
                      </button>
                      {ruleAddError && (
                        <p className="settings-error">{ruleAddError}</p>
                      )}
                      <small>
                        Правило будет добавлено в группу исключений с уровнем 0
                        и новым свободным номером.
                      </small>
                    </div>
                  )}
                </div>
              )
            )}
          </aside>
        </div>
      )}
      {historyOpen && (
        <div
          className="modal-backdrop"
          onMouseDown={() => setHistoryOpen(false)}
        >
          <aside
            className="history-panel"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="panel-top">
              <span className="ai-badge">✦ ИСТОРИЯ АНАЛИЗОВ</span>
              <button onClick={() => setHistoryOpen(false)}>×</button>
            </div>
            <div className="history-heading">
              <h2>Разобранные сигналы</h2>
              <p>
                Последние анализы доступны для быстрого возврата к контексту и
                решению AI.
              </p>
            </div>
            {!analysisHistory.length ? (
              <div className="empty-state">История пока пуста.</div>
            ) : (
              <div className="history-list">
                {analysisHistory.map((item) => {
                  const batchAlerts =
                    "alerts" in item.alert &&
                    Array.isArray((item.alert as { alerts?: unknown }).alerts)
                      ? (item.alert as { alerts: Record<string, unknown>[] })
                          .alerts
                      : [];
                  const alert = (
                    batchAlerts.length ? batchAlerts[0] : item.alert
                  ) as Partial<Alert>;
                  const count = batchAlerts.length || 1;
                  return (
                    <button
                      className={`history-item ${unreadAnalysisIds.has(item.id) ? "history-unread" : ""}`}
                      key={item.id}
                      onClick={() => {
                        setSelected(alert as Alert);
                        setSelectedAnalysisCount(count);
                        setAnalysis(item.analysis);
                        setAnalysisError("");
                        setRuleAddState("idle");
                        setUnreadAnalysisIds((current) => {
                          const next = new Set(current);
                          next.delete(item.id);
                          return next;
                        });
                        setHistoryOpen(false);
                      }}
                    >
                      <span>
                        <Level value={Number(alert.level) || 0} />
                        <strong>
                          {count > 1
                            ? `Пачка · ${count} алертов`
                            : String(alert.title || "Алерт")}
                        </strong>
                      </span>
                      <small>
                        {item.analysis.ruleAdded
                          ? `Правило ${item.analysis.ruleId || ""} добавлено`
                          : item.analysis.status === "processing"
                          ? "В обработке"
                          : item.analysis.status === "error"
                            ? "Ошибка"
                            : new Date(item.analyzedAt).toLocaleString("ru-RU")}
                        {!item.analysis.ruleAdded && item.analysis.status !== "error" && item.analysis.status !== "processing"
                          ? ` · ${String(alert.host || "")}`
                          : ""}
                      </small>
                    </button>
                  );
                })}
              </div>
            )}
          </aside>
        </div>
      )}
      {settingsOpen && (
        <div
          className="modal-backdrop settings-backdrop"
          onMouseDown={() => setSettingsOpen(false)}
        >
          <aside
            className="settings-panel"
            onMouseDown={(e) => e.stopPropagation()}
            aria-label="Настройки"
          >
            <div className="settings-top">
              <span className="settings-kicker">ЛОКАЛЬНАЯ КОНФИГУРАЦИЯ</span>
              <button
                onClick={() => setSettingsOpen(false)}
                aria-label="Закрыть"
              >
                ×
              </button>
            </div>
            <div className="settings-scroll">
              <div className="settings-heading">
                <h2>Настройки</h2>
                <p>Подключения и секреты хранятся только на этом компьютере.</p>
              </div>
              <SettingsGroup
                title="Wazuh SSH"
                health={health.wazuh}
                help="Для доступа через bastion укажите jump host. Ваш пример: jump host 150.241.76.111, пользователь root, порт 22; Wazuh host — localhost, пользователь wazuh-user, порт 2222. Это создаст ProxyJump-маршрут."
              >
                <Field
                  label="Wazuh host"
                  value={settings.WAZUH_SSH_HOST}
                  onChange={(v) => setSetting("WAZUH_SSH_HOST", v)}
                  placeholder="localhost"
                />
                <Field
                  label="Wazuh port"
                  value={settings.WAZUH_SSH_PORT}
                  onChange={(v) => setSetting("WAZUH_SSH_PORT", v)}
                  placeholder="2222"
                />
                <Field
                  label="Wazuh user"
                  value={settings.WAZUH_SSH_USER}
                  onChange={(v) => setSetting("WAZUH_SSH_USER", v)}
                  placeholder="wazuh-user"
                />
                <Field
                  label="Путь к ключу"
                  value={settings.WAZUH_SSH_PRIVATE_KEY_PATH}
                  onChange={(v) => setSetting("WAZUH_SSH_PRIVATE_KEY_PATH", v)}
                  placeholder="~/.ssh/id_rsa_wazuh"
                />
                <Field
                  label="Пароль SSH (альтернатива ключу)"
                  value={settings.WAZUH_SSH_PASSWORD}
                  onChange={(v) => setSetting("WAZUH_SSH_PASSWORD", v)}
                  secret
                  configured={Boolean(settings.WAZUH_SSH_PASSWORD_CONFIGURED)}
                />
                <Field
                  label="Или содержимое ключа"
                  value={settings.WAZUH_SSH_PRIVATE_KEY}
                  onChange={(v) => setSetting("WAZUH_SSH_PRIVATE_KEY", v)}
                  secret
                  configured={Boolean(
                    settings.WAZUH_SSH_PRIVATE_KEY_CONFIGURED,
                  )}
                  multiline
                />
                <Field
                  label="Jump host"
                  value={settings.WAZUH_SSH_JUMP_HOST}
                  onChange={(v) => setSetting("WAZUH_SSH_JUMP_HOST", v)}
                  placeholder="150.241.76.111"
                />
                <Field
                  label="Jump port"
                  value={settings.WAZUH_SSH_JUMP_PORT}
                  onChange={(v) => setSetting("WAZUH_SSH_JUMP_PORT", v)}
                  placeholder="22"
                />
                <Field
                  label="Jump user"
                  value={settings.WAZUH_SSH_JUMP_USER}
                  onChange={(v) => setSetting("WAZUH_SSH_JUMP_USER", v)}
                  placeholder="root"
                />
                <p className="fixed-command">
                  <span>Источник событий</span>
                  <code>Wazuh Indexer · wazuh-alerts-*</code>
                  <small>
                    Запрос выполняется напрямую к индексу через защищённое
                    SSH-подключение.
                  </small>
                </p>
              </SettingsGroup>
              <SettingsGroup
                title="AI API"
                health={health.ai}
                help="Введите Base URL и API-ключ, затем запросите список моделей у OpenAI-совместимого провайдера."
              >
                <Field
                  label="Base URL"
                  value={settings.OPENAI_BASE_URL}
                  onChange={(v) => setSetting("OPENAI_BASE_URL", v)}
                  placeholder="https://api.openai.com/v1"
                />
                <Field
                  label="API key"
                  value={settings.OPENAI_API_KEY}
                  onChange={(v) => setSetting("OPENAI_API_KEY", v)}
                  secret
                  configured={Boolean(settings.OPENAI_API_KEY_CONFIGURED)}
                />
                <button
                  type="button"
                  className="model-request-button wide-field"
                  onClick={requestModels}
                  disabled={
                    modelsLoading ||
                    !settings.OPENAI_BASE_URL ||
                    (!settings.OPENAI_API_KEY &&
                      !settings.OPENAI_API_KEY_CONFIGURED)
                  }
                >
                  {modelsLoading ? "ЗАПРАШИВАЮ МОДЕЛИ…" : "ЗАПРОСИТЬ МОДЕЛИ"}
                </button>
                <ModelField
                  value={settings.OPENAI_MODEL}
                  models={aiModels}
                  onChange={(v) => setSetting("OPENAI_MODEL", v)}
                />
              </SettingsGroup>
              {saveMessage && <div className="save-message">{saveMessage}</div>}
            </div>
            <div className="settings-actions">
              <button
                className="secondary-button"
                onClick={checkIntegrations}
                disabled={checking}
              >
                {checking ? "ПРОВЕРЯЮ…" : "ПРОВЕРИТЬ"}
              </button>
              <button
                className="check-button"
                onClick={saveSettings}
                disabled={saving}
              >
                {saving ? "СОХРАНЯЮ…" : "СОХРАНИТЬ"}
              </button>
            </div>
          </aside>
        </div>
      )}
    </main>
  );
}

function AuthLoading() {
  return (
    <main className="auth-screen">
      <div className="auth-card">
        <span className="brandmark">W</span>
        <p>Проверяю доступ Wazuh…</p>
      </div>
    </main>
  );
}
function Login({ onLogin }: { onLogin: (user: string) => void }) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ username, password }),
        }),
        data = await response.json();
      if (!response.ok)
        throw new Error(data.error || "Доменная авторизация не пройдена");
      onLogin(String(data.user || username));
      setPassword("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Ошибка входа");
    } finally {
      setLoading(false);
    }
  };
  return (
    <main className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">
          <span className="brandmark">W</span>
          <div>
            <b>Wazuh Journal</b>
            <small>ДОМЕННЫЙ ДОСТУП</small>
          </div>
        </div>
        <h1>Вход в SOC</h1>
        <p className="auth-help">Используйте доменную учётную запись Wazuh.</p>
        <label>
          <span>Доменный логин</span>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            placeholder="sAMAccountName"
            required
          />
        </label>
        <label>
          <span>Пароль</span>
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="auth-error">{error}</p>}
        <button className="check-button" disabled={loading}>
          {loading ? "ПРОВЕРЯЮ…" : "ВОЙТИ ЧЕРЕЗ WAZUH"}
        </button>
      </form>
    </main>
  );
}

function SettingsGroup({
  title,
  health,
  help,
  children,
}: {
  title: string;
  health: Health;
  help: string;
  children: React.ReactNode;
}) {
  return (
    <section className="settings-group">
      <div className="settings-group-head">
        <span className={`status-dot ${health.ok ? "" : "offline"}`} />
        <h3>{title}</h3>
        <b className={health.ok ? "ok" : "bad"}>
          {health.ok ? "РАБОТАЕТ" : "НЕ ПОДКЛЮЧЕНО"}
        </b>
      </div>
      <p className="settings-help-text">{help}</p>
      {!health.ok && <p className="settings-error">{health.error}</p>}
      <div className="field-grid">{children}</div>
    </section>
  );
}
function Field({
  label,
  value,
  onChange,
  placeholder,
  secret,
  configured,
  multiline,
}: {
  label: string;
  value: string | boolean | undefined;
  onChange: (value: string) => void;
  placeholder?: string;
  secret?: boolean;
  configured?: boolean;
  multiline?: boolean;
}) {
  const props = {
    value: typeof value === "string" ? value : "",
    onChange: (
      event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
    ) => onChange(event.target.value),
    placeholder:
      secret && configured
        ? "Сохранено — оставьте пустым, чтобы не менять"
        : placeholder,
  };
  return (
    <label className={multiline ? "wide-field" : ""}>
      <span>
        {label}
        {secret && configured && <i>СОХРАНЕНО</i>}
      </span>
      {multiline ? (
        <textarea {...props} rows={4} />
      ) : (
        <input
          {...props}
          type={secret ? "password" : "text"}
          autoComplete="off"
        />
      )}
    </label>
  );
}

function ModelField({
  value,
  models,
  onChange,
}: {
  value: string | boolean | undefined;
  models: string[];
  onChange: (value: string) => void;
}) {
  const selected = typeof value === "string" ? value : "";
  return (
    <label className="wide-field">
      <span>Модель</span>
      {models.length ? (
        <select
          value={selected}
          onChange={(event) => onChange(event.target.value)}
        >
          {!models.includes(selected) && selected && (
            <option>{selected}</option>
          )}
          {models.map((model) => (
            <option key={model} value={model}>
              {model}
            </option>
          ))}
        </select>
      ) : (
        <input
          value={selected}
          onChange={(event) => onChange(event.target.value)}
          placeholder="Сначала запросите модели или введите название вручную"
          autoComplete="off"
        />
      )}
    </label>
  );
}

function Feed({
  error,
  loading,
  batches,
  expanded,
  setExpanded,
  analyze,
  load,
  marked,
  skipped,
  setMarked,
  setSkipped,
  analyzedIds,
}: {
  error: string;
  loading: boolean;
  batches: Alert[][];
  expanded: string | null;
  setExpanded: (id: string | null) => void;
  analyze: (a: Alert | Alert[]) => void;
  load: () => void;
  marked: Set<string>;
  skipped: Set<string>;
  setMarked: React.Dispatch<React.SetStateAction<Set<string>>>;
  setSkipped: React.Dispatch<React.SetStateAction<Set<string>>>;
  analyzedIds: Set<string>;
}) {
  if (error && !batches.length)
    return (
      <section className="connection-error">
        <small>WAZUH SSH</small>
        <h1>Нет данных</h1>
        <p>{error}</p>
        <button onClick={load}>Повторить подключение</button>
      </section>
    );
  if (loading) return <div className="empty-state">Получаю события Wazuh…</div>;
  if (!batches.length)
    return (
      <div className="empty-state">
        Пачка формируется. Она появится после 5 алертов или через 5 минут.
      </div>
    );
  return (
    <>
      {error && (
        <div className="background-error">
          Не удалось обновить данные: {error}
        </div>
      )}
      {batches.map((batch) => {
        const isOpen = Boolean(
            expanded && batch.some((a) => a.id === expanded),
          ),
          first = batch[0].timestamp,
          last = batch[batch.length - 1].timestamp,
          priority = [...batch].sort((a, b) => b.level - a.level)[0];
        return (
          <article
            className={`batch ${batch.some((alert) => analyzedIds.has(alert.id)) ? "analyzed-batch" : ""}`}
            key={batch.map((a) => a.id).join("-")}
            data-expanded-anchor={isOpen ? expanded : undefined}
          >
            <button
              className="batch-head"
              onClick={() => setExpanded(isOpen ? null : batch[0].id)}
            >
              <div className="batch-time">
                <span>{batchDay(first)}</span>
                <small>
                  с {batchClock(last)}
                  <br />
                  до {batchClock(first)}
                </small>
              </div>
              <div className="severity">
                <span>
                  {batch.filter((a) => a.level >= 10).length} критичных
                </span>
                <span className="hostcount">
                  {new Set(batch.map((a) => a.host)).size} хостов
                </span>
              </div>
              <span className="chevron">{isOpen ? "↑" : "↓"}</span>
            </button>
            {!batch.every((alert) => analyzedIds.has(alert.id)) && (
              <button
                className="batch-analyze"
                onClick={(event) => {
                  event.stopPropagation();
                  analyze(batch);
                }}
              >
                Анализировать пачку <span>✦</span>
              </button>
            )}
            {isOpen && (
              <div className="alert-list">
                {batch.map((a, i) => (
                  <details
                    className={`alert-row ${analyzedIds.has(a.id) ? "analyzed-alert" : ""}`}
                    key={a.id}
                  >
                    <summary>
                      <div className="timeline">
                        <span>{a.time}</span>
                        <i>{i + 1}</i>
                      </div>
                      <div className="alert-main">
                        <div className="alert-title">
                          <Level value={a.level} />
                          <h2>{a.title}</h2>
                          <span className="expand-mark">+</span>
                        </div>
                      </div>
                    </summary>
                    <div className="alert-detail">
                      <h3>Что произошло</h3>
                      <p>
                        {a.story ||
                          `На хосте ${a.host} сработало правило ${a.rule} — ${a.title}.`}
                      </p>
                      <h3>Ключевые данные</h3>
                      <dl>
                        {(a.fields || []).map(([label, value]) => (
                          <React.Fragment key={label}>
                            <dt>{label}</dt>
                            <dd>{value}</dd>
                          </React.Fragment>
                        ))}
                      </dl>
                      <div className="alert-actions">
                        {!analyzedIds.has(a.id) && (
                          <button className="analyze" onClick={() => analyze(a)}>
                            Анализировать этот алерт <span>✦</span>
                          </button>
                        )}
                        <button
                          className={`secondary-button ${marked.has(a.id) ? "action-active" : ""}`}
                          onClick={(event) => {
                            event.preventDefault();
                            event.stopPropagation();
                            setMarked((current) => {
                              const next = new Set(current);
                              next.has(a.id)
                                ? next.delete(a.id)
                                : next.add(a.id);
                              return next;
                            });
                            setSkipped((current) => {
                              const next = new Set(current);
                              next.delete(a.id);
                              return next;
                            });
                          }}
                        >
                          {marked.has(a.id) ? "Снять пометку" : "Пометить"}
                        </button>
                        <button
                          className={`secondary-button ${skipped.has(a.id) ? "action-active" : ""}`}
                          onClick={(event) => {
                            event.preventDefault();
                            event.stopPropagation();
                            setSkipped((current) => {
                              const next = new Set(current);
                              next.has(a.id)
                                ? next.delete(a.id)
                                : next.add(a.id);
                              return next;
                            });
                            setMarked((current) => {
                              const next = new Set(current);
                              next.delete(a.id);
                              return next;
                            });
                          }}
                        >
                          {skipped.has(a.id) ? "Вернуть" : "Пропустить"}
                        </button>
                      </div>
                    </div>
                  </details>
                ))}
              </div>
            )}
          </article>
        );
      })}
    </>
  );
}
function BatchPager({
  page,
  pages,
  onChange,
}: {
  page: number;
  pages: number;
  onChange: (page: number) => void;
}) {
  const numbers = Array.from({ length: pages }, (_, index) => index);
  return (
    <nav className="batch-pager" aria-label="Страницы пачек">
      <button disabled={page === 0} onClick={() => onChange(page - 1)}>
        ←
      </button>
      {numbers.map((number) => (
        <button
          key={number}
          className={number === page ? "active" : ""}
          onClick={() => onChange(number)}
        >
          {number + 1}
        </button>
      ))}
      <button disabled={page === pages - 1} onClick={() => onChange(page + 1)}>
        →
      </button>
    </nav>
  );
}

function RulesTab({ alerts: _alerts }: { alerts: Alert[] }) {
  const [blocks, setBlocks] = useState<string[]>([]),
    [prefix, setPrefix] = useState(""),
    [message, setMessage] = useState("Загружаю правила…"),
    [saving, setSaving] = useState(false);
  useEffect(() => {
    fetch("/api/rules", { cache: "no-store" })
      .then(async (r) => {
        const data = await r.json();
        if (!r.ok) throw new Error(data.error);
        const xml = String(data.xml),
          groups = xml.match(/<group(?:\s|>)[\s\S]*?<\/group>/g) || [];
        setBlocks(groups);
        setPrefix(
          xml.slice(
            0,
            groups.length ? xml.indexOf(groups[0] || "") : xml.length,
          ),
        );
        setMessage("");
      })
      .catch((e) =>
        setMessage(e instanceof Error ? e.message : "Ошибка чтения"),
      );
  }, []);
  const save = async () => {
    setSaving(true);
    try {
      const r = await fetch("/api/rules", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ xml: prefix + blocks.join("\n\n") }),
        }),
        data = await r.json();
      if (!r.ok) throw new Error(data.error);
      setMessage("Правила сохранены; создана резервная копия");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="rules-view">
      <div className="rules-heading">
        <small>КОНСТРУКТОР ПРАВИЛ</small>
        <h1>Правила Wazuh</h1>
        <p>Служебная часть файла скрыта. Изменяются только группы и правила.</p>
      </div>
      <div className="rule-constructor-table">
        <div className="rule-construct-head">
          <span>Группа</span>
          <span>Правила в группе</span>
          <span>Действие</span>
        </div>
        {blocks.map((block, index) => (
          <div className="rule-construct-row" key={index}>
            <span>
              GROUP {index + 1}
              <small>{(block.match(/<rule\b/g) || []).length} правил</small>
            </span>
            <textarea
              value={block}
              onChange={(event) =>
                setBlocks((current) =>
                  current.map((value, i) =>
                    i === index ? event.target.value : value,
                  ),
                )
              }
              spellCheck={false}
            />
            <button
              className="secondary-button"
              onClick={() =>
                setBlocks((current) => current.filter((_, i) => i !== index))
              }
            >
              Удалить
            </button>
          </div>
        ))}
      </div>
      <button
        className="secondary-button"
        onClick={() =>
          setBlocks((current) => [
            ...current,
            '<group name="local,">\n  <rule id="100001" level="5">\n    <description>Новое правило</description>\n    <match>условие</match>\n  </rule>\n</group>',
          ])
        }
      >
        Добавить группу
      </button>
      {message && <p className="rules-message">{message}</p>}
      <button className="check-button" onClick={save} disabled={saving}>
        {saving ? "СОХРАНЯЮ…" : "СОХРАНИТЬ ПРАВИЛА"}
      </button>
    </div>
  );
}

function RuleConstructor() {
  const [groups, setGroups] = useState<string[]>([]),
    [prefix, setPrefix] = useState(""),
    [status, setStatus] = useState("Загрузка…"),
    [saving, setSaving] = useState(false);
  useEffect(() => {
    fetch("/api/rules")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error);
        const xml = String(data.xml),
          blocks = xml.match(/<group(?:\s|>)[\s\S]*?<\/group>/g) || [];
        setGroups(blocks);
        setPrefix(
          xml.slice(
            0,
            blocks.length ? xml.indexOf(blocks[0] || "") : xml.length,
          ),
        );
        setStatus("");
      })
      .catch((error) =>
        setStatus(error instanceof Error ? error.message : "Ошибка загрузки"),
      );
  }, []);
  const save = async () => {
    setSaving(true);
    try {
      const response = await fetch("/api/rules", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ xml: prefix + groups.join("\n\n") }),
      });
      if (!response.ok) throw new Error((await response.json()).error);
      setStatus("Сохранено; резервная копия создана");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="rules-view">
      <div className="rules-heading">
        <small>КОНСТРУКТОР</small>
        <h1>Правила Wazuh</h1>
        <p>Служебная часть скрыта. Редактируются только блоки group и rule.</p>
      </div>
      <div className="rule-constructor-table">
        <div className="rule-construct-head">
          <span>Группа / правило</span>
          <span>Редактор блока</span>
          <span>Действие</span>
        </div>
        {groups.map((group, index) => (
          <div className="rule-construct-row" key={index}>
            <span>
              GROUP {index + 1}
              <small>{(group.match(/<rule\b/g) || []).length} правил</small>
            </span>
            <textarea
              value={group}
              onChange={(event) =>
                setGroups((current) =>
                  current.map((value, i) =>
                    i === index ? event.target.value : value,
                  ),
                )
              }
              spellCheck={false}
            />
            <button
              className="secondary-button"
              onClick={() =>
                setGroups((current) => current.filter((_, i) => i !== index))
              }
            >
              Удалить
            </button>
          </div>
        ))}
      </div>
      <button
        className="secondary-button"
        onClick={() =>
          setGroups((current) => [
            ...current,
            '<group name="local,">\n  <rule id="100001" level="5">\n    <description>Новое правило</description>\n    <match>условие</match>\n  </rule>\n</group>',
          ])
        }
      >
        Добавить группу
      </button>
      {status && <p className="rules-message">{status}</p>}
      <button className="check-button" onClick={save} disabled={saving}>
        {saving ? "СОХРАНЯЮ…" : "СОХРАНИТЬ ПРАВИЛА"}
      </button>
    </div>
  );
}

type RuleCard = { id: string; level: string; body: string };
type RuleGroup = { name: string; rules: RuleCard[]; exception?: boolean };
function parseRuleGroups(xml: string): { prefix: string; groups: RuleGroup[] } {
  const doc = new DOMParser().parseFromString(
      `<root>${xml}</root>`,
      "application/xml",
    ),
    serializer = new XMLSerializer(),
    root = doc.documentElement;
  const groupNodes = Array.from(root.children).filter(
    (node) => node.tagName === "group",
  );
  const groups = groupNodes
    .map((node) => {
      const name = node.getAttribute("name") || "local";
      const rules = Array.from(node.children)
        .filter((child) => child.tagName === "rule")
        .map((rule) => ({
          id: rule.getAttribute("id") || "—",
          level: rule.getAttribute("level") || "0",
          body: Array.from(rule.childNodes)
            .map((child) => serializer.serializeToString(child))
            .join("")
            .trim(),
        }));
      return { name, rules, exception: /exception|исключ|except/i.test(name) };
    })
    .filter((group) => group.rules.length > 0);
  const first = xml.search(/<group\s+name=/);
  return { prefix: first >= 0 ? xml.slice(0, first) : "", groups };
}
function RuleConstructorV2() {
  const [prefix, setPrefix] = useState(""),
    [groups, setGroups] = useState<RuleGroup[]>([]),
    [status, setStatus] = useState("Загрузка…"),
    [saving, setSaving] = useState(false);
  useEffect(() => {
    fetch("/api/rules", { cache: "no-store" })
      .then(async (r) => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.error);
        const parsed = parseRuleGroups(String(d.xml));
        setPrefix(parsed.prefix);
        setGroups(parsed.groups);
        setStatus("");
      })
      .catch((e) =>
        setStatus(e instanceof Error ? e.message : "Ошибка загрузки"),
      );
  }, []);
  const updateGroup = (index: number, patch: Partial<RuleGroup>) =>
    setGroups((current) =>
      current.map((g, i) => (i === index ? { ...g, ...patch } : g)),
    );
  const save = async () => {
    setSaving(true);
    try {
      const xml =
        prefix +
        groups
          .map(
            (g) =>
              `<group name="${g.name}">\n${g.rules
                .map(
                  (r) =>
                    `  <rule id="${r.id}" level="${r.level}">\n${r.body
                      .split("\n")
                      .map((line) => `    ${line}`)
                      .join("\n")}\n  </rule>`,
                )
                .join("\n")}\n</group>`,
          )
          .join("\n\n");
      const response = await fetch("/api/rules", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ xml }),
      });
      if (!response.ok) throw new Error((await response.json()).error);
      setStatus("Сохранено; резервная копия создана");
    } catch (e) {
      setStatus(e instanceof Error ? e.message : "Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="rules-view">
      <div className="rules-heading">
        <small>КОНСТРУКТОР ПРАВИЛ</small>
        <h1>Правила Wazuh</h1>
        <p>
          Служебные XML-поля скрыты. Редактируйте название группы, уровень и
          содержимое правила.
        </p>
      </div>
      <div className="rules-cards">
        {groups.map((group, gi) => (
          <details
            className={`rule-group-card ${group.exception ? "exception-group" : ""}`}
            key={`${group.name}-${gi}`}
          >
            <summary className="rule-group-head">
              <div>
                <small>{group.exception ? "ИСКЛЮЧЕНИЯ" : "ГРУППА"}</small>
                <input
                  onClick={(e) => e.stopPropagation()}
                  value={group.name}
                  onChange={(e) => updateGroup(gi, { name: e.target.value })}
                />
              </div>
              <span>
                {group.rules.length} правил <i>⌄</i>
              </span>
            </summary>
            {group.rules.map((rule, ri) => (
              <article className="rule-card" key={`${rule.id}-${ri}`}>
                <div className="rule-card-head">
                  <strong>Правило {rule.id}</strong>
                  <label>
                    Уровень{" "}
                    <input
                      type="number"
                      min="0"
                      max="16"
                      value={rule.level}
                      onChange={(e) =>
                        updateGroup(gi, {
                          rules: group.rules.map((r, i) =>
                            i === ri ? { ...r, level: e.target.value } : r,
                          ),
                        })
                      }
                    />
                  </label>
                </div>
                <textarea
                  value={rule.body}
                  onChange={(e) =>
                    updateGroup(gi, {
                      rules: group.rules.map((r, i) =>
                        i === ri ? { ...r, body: e.target.value } : r,
                      ),
                    })
                  }
                  spellCheck={false}
                />
              </article>
            ))}
          </details>
        ))}
      </div>
      {status && <p className="rules-message">{status}</p>}
      <div className="rules-actions">
        <button
          className="secondary-button"
          onClick={() =>
            setGroups((current) => [
              ...current,
              {
                name: "exceptions",
                exception: true,
                rules: [
                  {
                    id: "100900",
                    level: "5",
                    body: "<description>Новое исключение</description>\n<match>условие</match>",
                  },
                ],
              },
            ])
          }
        >
          Добавить исключение
        </button>
        <button className="check-button" onClick={save} disabled={saving}>
          {saving ? "СОХРАНЯЮ…" : "СОХРАНИТЬ ПРАВИЛА"}
        </button>
      </div>
    </div>
  );
}
