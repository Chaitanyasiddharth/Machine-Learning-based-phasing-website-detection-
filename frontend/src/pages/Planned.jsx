import { Icon, PageHeader } from "../components.jsx";

function PlannedModule({ title, phase, purpose, features, model, children }) {
  return (
    <>
      <PageHeader title={title} subtitle={purpose} />
      <div className="card planned">
        <div className="planned-banner">
          <Icon name="info" />
          <div>
            <strong>Not built yet — planned for {phase}.</strong>
            <p className="muted small">This page shows what the module will do. It does not analyse anything yet, and no results here are simulated.</p>
          </div>
        </div>
        <div className="planned-preview" aria-disabled="true">{children}</div>
        <div className="planned-grid">
          <section>
            <h3>Planned checks</h3>
            <ul className="bullet">{features.map((f) => <li key={f}>{f}</li>)}</ul>
          </section>
          <section>
            <h3>Planned model</h3>
            <p>{model}</p>
          </section>
        </div>
      </div>
    </>
  );
}

export function WebsiteAnalyzer() {
  return (
    <PlannedModule title="Website Analyzer" phase="Phase 3"
      purpose="Inspects a website's HTML and structure for signs that it is fake."
      model="XGBoost on safely collected page features. Pages are fetched without running their JavaScript, with timeouts, size limits and blocking of private network addresses."
      features={["Login and password form detection", "External link analysis", "Redirect inspection",
        "Suspicious domain characteristics", "Website security indicators"]}>
      <label className="label">Website URL</label>
      <div className="scan-row">
        <input type="text" placeholder="https://example.com" disabled />
        <button className="btn primary" disabled>Inspect</button>
      </div>
    </PlannedModule>
  );
}

export function MessageAnalyzer() {
  return (
    <PlannedModule title="Message Analyzer" phase="Phase 4"
      purpose="Uses natural-language processing to spot manipulative or fraudulent messages."
      model="TF-IDF with Multinomial Naive Bayes, with DistilBERT as an optional advanced model. It needs a labelled message dataset first."
      features={["Urgency and fear-based language", "Fake authority and impersonation", "Suspicious payment requests",
        "Credential collection requests", "Fraudulent reward and prize claims"]}>
      <label className="label">Message text</label>
      <textarea rows={5} placeholder="Paste an email, SMS or chat message…" disabled />
      <button className="btn primary" disabled>Analyze message</button>
    </PlannedModule>
  );
}
