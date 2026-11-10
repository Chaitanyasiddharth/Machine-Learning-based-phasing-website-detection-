import { useEffect, useState } from "react";
import { api } from "../api.js";
import { ErrorBox, PageHeader, ResultView, Spinner } from "../components.jsx";

const EXAMPLES = [
  "https://en.wikipedia.org/wiki/Phishing",
  "http://paypal.com.account-verify-login.xyz/webscr?cmd=_login",
  "http://192.168.12.7/secure/bank/update.php",
];

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [save, setSave] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [thresholds, setThresholds] = useState(null);

  useEffect(() => {
    api.info().then((i) => setThresholds(i.url_model?.risk_thresholds ?? null)).catch(() => {});
  }, []);

  async function analyze(e) {
    e?.preventDefault();
    const value = url.trim();
    if (!value) {
      setError("Enter a URL to analyse.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await api.analyzeUrl(value, save));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <PageHeader title="URL Scanner"
        subtitle="Checks the text of a URL with the trained machine-learning model. The site itself is never visited." />
      <form className="card scan-form" onSubmit={analyze}>
        <label htmlFor="url-input" className="label">URL to analyse</label>
        <div className="scan-row">
          <input id="url-input" type="text" inputMode="url" autoComplete="off" spellCheck="false"
            placeholder="https://example.com/login" value={url} maxLength={2048}
            onChange={(e) => setUrl(e.target.value)} disabled={loading} />
          <button className="btn primary" type="submit" disabled={loading}>
            {loading ? "Analysing…" : "Analyze"}
          </button>
        </div>
        <div className="scan-options">
          <label className="check">
            <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
            Save to history (the query string and any login details are removed first)
          </label>
        </div>
        <div className="examples">
          <span className="muted small">Try:</span>
          {EXAMPLES.map((ex) => (
            <button type="button" key={ex} className="chip" onClick={() => setUrl(ex)} disabled={loading}>{ex}</button>
          ))}
        </div>
      </form>

      {loading && <Spinner label="Running the model…" />}
      {error && <ErrorBox>{error}</ErrorBox>}
      {result && <ResultView result={result} thresholds={thresholds} />}
    </>
  );
}
