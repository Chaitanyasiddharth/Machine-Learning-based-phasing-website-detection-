const PATHS = {
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  link: "M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z",
  message: "M4 5h16v11H8l-4 4z",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  cog: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  menu: "M4 6h16M4 12h16M4 18h16",
  shield: "M12 3 5 6v6c0 4.4 3 8.1 7 9 4-.9 7-4.6 7-9V6z",
  alert: "M12 4 2.5 20h19zM12 10v4M12 17.5v.01",
  check: "M5 12.5l4.5 4.5L19 7",
  arrowLeft: "M15 6l-6 6 6 6",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5v.01",
};

export function Icon({ name, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}

export function riskClass(risk) {
  if (!risk) return "";
  if (risk.startsWith("HIGH")) return "high";
  if (risk.startsWith("MEDIUM")) return "medium";
  return "low";
}

export function RiskBadge({ risk }) {
  return <span className={`risk-badge ${riskClass(risk)}`}>{risk}</span>;
}

export function Verdict({ prediction }) {
  const phish = prediction === "phishing";
  return (
    <span className={`verdict ${phish ? "phish" : "legit"}`}>
      <Icon name={phish ? "alert" : "check"} size={15} />
      {phish ? "Phishing" : "Legitimate"}
    </span>
  );
}

export function Spinner({ label }) {
  return (
    <div className="spinner-wrap" role="status">
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorBox({ children }) {
  return (
    <div className="error-box" role="alert">
      <Icon name="alert" /> <span>{children}</span>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

function ProbabilityMeter({ p, thresholds }) {
  const pctVal = Math.round(p * 1000) / 10;
  return (
    <div className="meter">
      <div className="meter-head">
        <span>Phishing probability</span>
        <strong>{pctVal}%</strong>
      </div>
      <div className="meter-track">
        <div className={`meter-fill ${p >= 0.5 ? "hi" : p >= 0.3 ? "mid" : "lo"}`} style={{ width: `${pctVal}%` }} />
        {thresholds && (
          <>
            <span className="meter-mark" style={{ left: `${thresholds.low * 100}%` }} title="Medium-risk threshold" />
            <span className="meter-mark" style={{ left: `${thresholds.high * 100}%` }} title="High-risk threshold" />
          </>
        )}
      </div>
    </div>
  );
}

export function ResultView({ result, thresholds }) {
  return (
    <div className={`card result ${riskClass(result.risk_category)}`}>
      <div className="result-top">
        <div className="result-url" title={result.input}>{result.input}</div>
        <div className="result-tags">
          <Verdict prediction={result.prediction} />
          <RiskBadge risk={result.risk_category} />
        </div>
      </div>
      <ProbabilityMeter p={result.phishing_probability} thresholds={thresholds} />

      <div className="result-grid">
        <section>
          <h3>Suspicious indicators</h3>
          <p className="muted small">Rule-based checks on the URL text, shown alongside the model output.</p>
          {result.indicators.length === 0 ? (
            <p className="empty-line">No rule-based warning signs found.</p>
          ) : (
            <ul className="indicators">
              {result.indicators.map((i) => (
                <li key={i.code} className={`sev-${i.severity}`}>
                  <span className="sev">{i.severity}</span>
                  <span>{i.message}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3>Why the model decided this</h3>
          <p className="muted small">Largest contributions in the Logistic Regression model for this URL.</p>
          {result.model_reasons.length === 0 ? (
            <p className="empty-line">No per-URL explanation available for this model.</p>
          ) : (
            <ul className="reasons">
              {result.model_reasons.map((r, idx) => (
                <li key={idx}>
                  <span className={`dir ${r.direction.includes("phishing") ? "toward-phish" : "toward-legit"}`}>
                    {r.direction.includes("phishing") ? "▲ phishing" : "▼ legitimate"}
                  </span>
                  <span className="feat">{r.feature}</span>
                  <span className="contrib">{r.contribution > 0 ? "+" : ""}{r.contribution.toFixed(2)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <p className="note"><Icon name="info" size={15} /> {result.note} Model: {result.model}.</p>
    </div>
  );
}
