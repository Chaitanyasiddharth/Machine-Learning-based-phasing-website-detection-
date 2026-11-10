import { useEffect, useState } from "react";
import { api, formatTime, pct } from "../api.js";
import { ErrorBox, Icon, PageHeader, RiskBadge, Spinner, Verdict } from "../components.jsx";

function Stat({ label, value, tone, hint }) {
  return (
    <div className={`card stat ${tone || ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

function RiskBreakdown({ byRisk, total }) {
  const rows = [["HIGH RISK", "high"], ["MEDIUM RISK", "medium"], ["LOW RISK", "low"]];
  return (
    <div className="breakdown">
      {rows.map(([key, cls]) => {
        const n = byRisk[key] || 0;
        const share = total ? n / total : 0;
        return (
          <div className="bd-row" key={key}>
            <span className="bd-label">{key}</span>
            <div className="bd-track"><div className={`bd-fill ${cls}`} style={{ width: `${share * 100}%` }} /></div>
            <span className="bd-num">{n}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.stats(), api.history(8), api.info()])
      .then(([s, h, i]) => { setStats(s); setRecent(h); setInfo(i); })
      .catch((e) => setError(e.message));
  }, []);

  if (error) return (<><PageHeader title="Dashboard" /><ErrorBox>{error}</ErrorBox></>);
  if (!stats) return <Spinner label="Loading dashboard…" />;

  const report = info?.training_report;
  const sel = report?.models?.[report.selected_model];
  const totalRisk = Object.values(stats.by_risk_category).reduce((a, b) => a + b, 0);

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Counts come from the analyses saved in this app's history.">
        <a className="btn primary" href="#/scan"><Icon name="link" /> Scan a URL</a>
      </PageHeader>

      <div className="stats-grid">
        <Stat label="URLs analysed" value={stats.total_urls_analyzed} />
        <Stat label="Phishing URLs detected" value={stats.phishing_urls_detected} tone="danger" />
        <Stat label="Legitimate URLs" value={stats.legitimate_urls_detected} tone="safe" />
        <Stat label="Messages analysed" value={stats.suspicious_messages_analyzed} tone="muted"
          hint="Message Analyzer not built yet" />
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-head">
            <h2>Recent activity</h2>
            <a href="#/history" className="link">View all</a>
          </div>
          {recent.length === 0 ? (
            <div className="empty">
              <Icon name="shield" size={28} />
              <p>No analyses yet. Scan a URL to see it here.</p>
            </div>
          ) : (
            <ul className="recent">
              {recent.map((r) => (
                <li key={r.id}>
                  <a href={`#/history/${r.id}`}>
                    <span className="recent-url" title={r.input_redacted}>{r.input_redacted}</span>
                    <span className="recent-meta">
                      <Verdict prediction={r.prediction} />
                      <RiskBadge risk={r.risk_category} />
                      <span className="muted small">{formatTime(r.created_at)}</span>
                    </span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="side-stack">
          <div className="card">
            <h2>Detection summary</h2>
            {totalRisk === 0 ? <p className="muted">Nothing analysed yet.</p>
              : <RiskBreakdown byRisk={stats.by_risk_category} total={totalRisk} />}
          </div>
          <div className="card">
            <h2>URL model</h2>
            {sel ? (
              <dl className="kv">
                <dt>Model</dt><dd>{report.selected_model.replace("_", " ")}</dd>
                <dt>Test F1</dt><dd>{sel.test.f1.toFixed(3)}</dd>
                <dt>External-set F1</dt><dd>{sel.external_test.f1.toFixed(3)}</dd>
                <dt>False positive rate (external)</dt><dd>{pct(sel.external_test.false_positive_rate)}</dd>
              </dl>
            ) : <p className="muted">No training report found.</p>}
            <a href="#/settings" className="link">Full evaluation →</a>
          </div>
        </div>
      </div>
    </>
  );
}
