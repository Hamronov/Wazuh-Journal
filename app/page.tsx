"use client";

import { useState } from "react";

type Alert = {
  id: string; time: string; level: number; title: string; host: string;
  ip: string; rule: string; group: string; detail: string; falsePositive: number;
};

const alerts: Alert[] = [
  { id: "012942.18474", time: "14:32:08", level: 12, title: "Множественные ошибки входа", host: "dc-01.corp.local", ip: "10.24.1.18", rule: "5712", group: "authentication_failed", detail: "9 неуспешных попыток входа для svc_backup за 64 секунды. Источник ранее не наблюдался на контроллере домена.", falsePositive: 18 },
  { id: "012941.18462", time: "14:31:52", level: 10, title: "Изменение группы Domain Admins", host: "dc-01.corp.local", ip: "10.24.3.44", rule: "60154", group: "group_changed", detail: "Пользователь m.kuznetsov добавил учетную запись temp.audit в привилегированную группу.", falsePositive: 7 },
  { id: "012940.18441", time: "14:30:19", level: 8, title: "PowerShell с кодированной командой", host: "ws-fin-023", ip: "10.24.18.23", rule: "91815", group: "powershell", detail: "powershell.exe запущен с параметром -EncodedCommand из процесса winword.exe.", falsePositive: 24 },
  { id: "012938.18394", time: "14:28:44", level: 7, title: "Подозрительное изменение файла", host: "web-prod-02", ip: "10.24.8.12", rule: "550", group: "syscheck", detail: "Изменен /etc/ssh/sshd_config. Контрольная сумма не совпадает с предыдущей ревизией.", falsePositive: 42 },
  { id: "012937.18371", time: "14:27:03", level: 6, title: "Сканирование портов", host: "fw-edge-01", ip: "185.220.101.17", rule: "40211", group: "firewall", detail: "Зафиксировано 38 последовательных соединений к закрытым портам из внешней сети.", falsePositive: 61 },
];

function Level({ value }: { value: number }) {
  return <span className={`level l${value >= 10 ? "high" : value >= 7 ? "med" : "low"}`}>L{value}</span>;
}

export default function Home() {
  const [open, setOpen] = useState(true);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<Alert | null>(null);
  const [ruleAdded, setRuleAdded] = useState(false);
  const [filter, setFilter] = useState("Все уровни");

  const analyze = async (alert: Alert) => {
    setSelected(alert); setResult(null); setRuleAdded(false); setAnalyzing(true);
    try {
      const response = await fetch("/api/analyze", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(alert) });
      const data = await response.json();
      setResult({ ...alert, falsePositive: Number.isFinite(data.falsePositive) ? data.falsePositive : alert.falsePositive });
    } catch { setResult(alert); }
    finally { window.setTimeout(() => setAnalyzing(false), 500); }
  };

  return (
    <main>
      <header className="topbar">
        <div className="brand"><span className="brandmark">W</span><span>Wazuh<br/>Journal</span></div>
        <nav><button className="nav-active">Лента</button><button>Правила</button><button>Источники</button></nav>
        <div className="user"><span className="status-dot"/><span><b>Максим Орлов</b><small>SECURITY ANALYST</small></span><span className="avatar">МО</span></div>
      </header>

      <section className="hero">
        <div className="eyebrow"><span className="live-dot"/> ПРЯМОЙ ЭФИР · ОБНОВЛЕНО 12 СЕК НАЗАД</div>
        <div className="hero-row">
          <div><h1>Сигналы, которые<br/><em>стоит увидеть.</em></h1><p>Поток алертов Wazuh, собранный в ясную ленту.<br/>Без шума — с контекстом и AI-анализом.</p></div>
          <div className="hero-stat"><span>Сегодня</span><strong>147</strong><small>АЛЕРТОВ</small><div className="bars"><i/><i/><i/><i/><i/><i/><i/></div></div>
        </div>
      </section>

      <section className="workspace">
        <div className="toolbar">
          <div className="date"><button>‹</button><span><small>ВТОРНИК</small>21 июля 2026</span><button>›</button></div>
          <div className="filters"><button className="filter-primary">Новые <span>12</span></button><button>Критичные <span>3</span></button><button onClick={() => setFilter(filter === "Все уровни" ? "L10+" : "Все уровни")}>{filter}⌄</button></div>
        </div>

        <article className={`batch ${open ? "expanded" : ""}`}>
          <button className="batch-head" onClick={() => setOpen(!open)} aria-expanded={open}>
            <div className="batch-time"><span>14:27–14:32</span><small>5 АЛЕРТОВ · 5 МИНУТ</small></div>
            <div className="severity"><Level value={12}/><span>2 критичных</span><span className="hostcount">4 хоста</span></div>
            <span className="chevron">{open ? "↑" : "↓"}</span>
          </button>
          {open && <div className="alert-list">
            {alerts.map((alert, index) => <div className="alert-row" key={alert.id}>
              <div className="timeline"><span>{alert.time}</span><i>{index + 1}</i></div>
              <div className="alert-main"><div className="alert-title"><Level value={alert.level}/><h2>{alert.title}</h2></div><p>{alert.detail}</p><div className="meta"><span>⌁ {alert.host}</span><span>◎ {alert.ip}</span><span>RULE {alert.rule}</span></div></div>
              <button className="analyze" onClick={() => analyze(alert)}>Анализировать <span>✦</span></button>
            </div>)}
          </div>}
        </article>

        <article className="batch compact"><button className="batch-head"><div className="batch-time"><span>14:18–14:23</span><small>5 АЛЕРТОВ · 5 МИНУТ</small></div><div className="severity"><Level value={8}/><span>1 высокий</span><span className="hostcount">3 хоста</span></div><span className="chevron">↓</span></button></article>
        <article className="batch compact"><button className="batch-head"><div className="batch-time"><span>14:07–14:12</span><small>5 АЛЕРТОВ · 5 МИНУТ</small></div><div className="severity"><Level value={5}/><span>низкий риск</span><span className="hostcount">5 хостов</span></div><span className="chevron">↓</span></button></article>
      </section>

      <footer><span>WAZUH JOURNAL / SOC-01</span><span><i className="status-dot"/> SSH · ПОДКЛЮЧЕНО</span><span>15 СЕК ДО ОБНОВЛЕНИЯ</span></footer>

      {selected && <div className="modal-backdrop" onMouseDown={() => setSelected(null)}>
        <aside className="analysis-panel" onMouseDown={e => e.stopPropagation()}>
          <div className="panel-top"><span className="ai-badge">✦ AI АНАЛИЗ</span><button onClick={() => setSelected(null)}>×</button></div>
          <div className="panel-heading"><Level value={selected.level}/><h2>{selected.title}</h2><p>{selected.host} · {selected.time} · RULE {selected.rule}</p></div>
          {analyzing ? <div className="loading"><div className="orb">✦</div><h3>Изучаю сигнал</h3><p>Отправляю краткий контекст одного алерта,<br/>без данных соседних событий.</p><span/><span/><span/></div> : result && <div className="result">
            <section className="verdict"><div><small>ШАНС ЛОЖНОГО СРАБАТЫВАНИЯ</small><strong>{result.falsePositive}%</strong></div><div className="meter"><i style={{width: `${result.falsePositive}%`}}/></div><p>{result.falsePositive < 30 ? "Сигнал выглядит обоснованным. Рекомендуется проверить пользователя и исходный хост." : "Есть признаки штатной административной активности, но требуется подтверждение владельца системы."}</p></section>
            <section><small>КРАТКИЙ ВЫВОД</small><h3>{result.falsePositive < 30 ? "Требует внимания аналитика" : "Вероятно допустимая активность"}</h3><p>Событие совпадает с техникой MITRE ATT&CK и отклоняется от обычного профиля узла. Контекст проанализирован только для этого алерта.</p></section>
            <section className="rule-box"><div className="rule-label"><span>ПРЕДЛОЖЕННОЕ ПРАВИЛО</span><span>XML</span></div><code>{`<rule id="100${result.rule}" level="0">\n  <if_sid>${result.rule}</if_sid>\n  <field name="agent.name">${result.host}</field>\n  <description>Approved activity</description>\n</rule>`}</code></section>
            {ruleAdded ? <div className="success">✓ Правило добавлено в черновики</div> : <div className="actions"><button className="add-rule" onClick={() => setRuleAdded(true)}>Добавить правило <span>＋</span></button><button className="reject" onClick={() => setSelected(null)}>Отклонить</button></div>}
          </div>}
        </aside>
      </div>}
    </main>
  );
}
