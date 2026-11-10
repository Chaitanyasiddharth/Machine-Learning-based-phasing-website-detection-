import { useEffect, useState } from "react";
import { api, formatTime, pct } from "../api.js";
import { ErrorBox, PageHeader, Spinner } from "../components.jsx";

const n = (v) => (v == null ? "–" : v.toLocaleString());
const f3 = (v) => (v == null ? "–" : v.toFixed(3));

const LIMITATIONS = [
  "Accuracy falls on a separately collected URL set (F1 0.915 on the internal test vs 0.839 on the external set).",
  "Words like “account” and “signin” weigh heavily, so some real sign-in pages (e.g. accounts.google.com/signin) are flagged.",
  "Shortened links (bit.ly, …) score as phishing because most shortened links in the training data were phishing.",
  "The MEDIUM risk band is very narrow; the risk thresholds need rework.",
  "Only the URL text is analysed. Website content and messages are not checked yet.",
];

export default function Settings() {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { api.info().then(setInfo).catch((e) => setError(e.message)); }, []);

  if (error) return (<><PageHeader title="Model & Settings" /><ErrorBox>{error}</ErrorBox></>);
  if (!info) return <Spinner label="Loading…" />;

  const m = info.url_model;
  const report = info.training_report;
  const ds = m?.dataset;
  const models = report ? Object.entries(report.models) : [];
  const selected = report?.models?.[report.selected_model];

  return (
    <>
      <PageHeader title="Model & Settings" subtitle="Model, dataset and version details, with evaluation numbers from the last training run." />

      <div className="two-col even">
        <div className="card">
          <h2>Application</h2>
          <dl className="kv">
            <dt>Name</dt><dd>{info.application}</dd>
            <dt>Version</dt><dd>{info.version} (prototype)</dd>
          </dl>
          <h3>Modules</h3>
          <ul className="modules">
            {Object.entries(info.modules).map(([k, v]) => (
              <li key={k}><span>{k.replace(/_/g, " ")}</span>
                <span className={`mod-status ${v === "implemented" ? "ok" : v.startsWith("partial") ? "part" : "plan"}`}>{v}</span></li>
            ))}
          </ul>
        </div>
        <div className="card">
          <h2>URL model</h2>
          {m?.model_name ? (
            <dl className="kv">
              <dt>Algorithm</dt><dd>{m.model_name.replace("_", " ")}</dd>
              <dt>Features</dt><dd>Character 3–5-gram TF-IDF + 27 URL features</dd>
              <dt>Trained</dt><dd>{formatTime(m.trained_at)}</dd>
              <dt>Decision threshold</dt><dd>{m.decision_threshold}</dd>
              <dt>Risk thresholds</dt><dd>LOW &lt; {m.risk_thresholds.low} ≤ MEDIUM &lt; {m.risk_thresholds.high} ≤ HIGH</dd>
            </dl>
          ) : <p className="muted">No model loaded. Train it with scripts/train_url_model.py.</p>}
        </div>
      </div>

      {ds && (
        <div className="card">
          <h2>Datasets</h2>
          <div className="two-col even tight">
            <div>
              <h3>Training data</h3>
              <p><code>{ds.train_source.id}</code> ({ds.train_source.file})</p>
              <dl className="kv">
                <dt>Raw rows</dt><dd>{n(ds.main_raw_rows)}</dd>
                <dt>After cleaning</dt><dd>{n(ds.main_clean_rows)}</dd>
                <dt>Train / validation / test</dt><dd>{n(ds.train_rows)} / {n(ds.validation_rows)} / {n(ds.test_rows)}</dd>
                <dt>Split</dt><dd>Grouped by domain; no domain in more than one split</dd>
              </dl>
            </div>
            <div>
              <h3>External test data</h3>
              <p><code>{ds.external_test_source.id}</code></p>
              <dl className="kv">
                <dt>Rows used</dt><dd>{n(ds.external_rows)}</dd>
                <dt>Phishing share</dt><dd>{pct(ds.external_phishing_ratio)}</dd>
                <dt>Overlap removed from training</dt><dd>{n(ds.main_rows_removed_overlap_with_external)} URLs</dd>
              </dl>
            </div>
          </div>
        </div>
      )}

      {report && (
        <div className="card table-card">
          <h2>Model comparison</h2>
          <p className="muted small">Selected by {report.selection_criterion}. Each test set was scored once, after selection.</p>
          <div className="table-scroll">
            <table className="table static">
              <thead>
                <tr><th>Model</th><th>Data</th><th className="num">Accuracy</th><th className="num">Precision</th>
                  <th className="num">Recall</th><th className="num">F1</th><th className="num">ROC-AUC</th>
                  <th className="num">False pos.</th><th className="num">False neg.</th></tr>
              </thead>
              <tbody>
                {models.flatMap(([name, mm]) => [["Internal test", mm.test], ["External set", mm.external_test]]
                  .filter(([, x]) => x)
                  .map(([label, x]) => (
                    <tr key={name + label} className={name === report.selected_model ? "selected" : ""}>
                      <td>{name.replace("_", " ")}{name === report.selected_model && label === "Internal test" ? " ★" : ""}</td>
                      <td className="muted">{label} ({n(x.n)})</td>
                      <td className="num">{f3(x.accuracy)}</td><td className="num">{f3(x.precision)}</td>
                      <td className="num">{f3(x.recall)}</td><td className="num">{f3(x.f1)}</td>
                      <td className="num">{f3(x.roc_auc)}</td>
                      <td className="num">{pct(x.false_positive_rate)}</td><td className="num">{pct(x.false_negative_rate)}</td>
                    </tr>
                  )))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected?.test && (
        <div className="two-col even">
          <div className="card">
            <h2>Confusion matrix (internal test)</h2>
            <div className="cm">
              <div /><div className="cm-h">Predicted legit</div><div className="cm-h">Predicted phishing</div>
              <div className="cm-h">Actually legit</div><div className="cm-c good">{n(selected.test.confusion_matrix.tn)}</div><div className="cm-c bad">{n(selected.test.confusion_matrix.fp)}</div>
              <div className="cm-h">Actually phishing</div><div className="cm-c bad">{n(selected.test.confusion_matrix.fn)}</div><div className="cm-c good">{n(selected.test.confusion_matrix.tp)}</div>
            </div>
          </div>
          <div className="card">
            <h2>Risk bands: how often each level was really phishing</h2>
            <div className="table-scroll">
            <table className="table static">
              <thead><tr><th>Band</th><th className="num">Test: share / phishing</th><th className="num">External: share / phishing</th></tr></thead>
              <tbody>
                {["LOW RISK", "MEDIUM RISK", "HIGH RISK"].map((b) => (
                  <tr key={b}><td>{b}</td>
                    <td className="num">{pct(selected.test_risk_bands?.[b]?.share_of_inputs)} / {pct(selected.test_risk_bands?.[b]?.actual_phishing_rate)}</td>
                    <td className="num">{pct(selected.external_risk_bands?.[b]?.share_of_inputs)} / {pct(selected.external_risk_bands?.[b]?.actual_phishing_rate)}</td></tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Known limitations</h2>
        <ul className="bullet">{LIMITATIONS.map((l) => <li key={l}>{l}</li>)}</ul>
      </div>
    </>
  );
}
