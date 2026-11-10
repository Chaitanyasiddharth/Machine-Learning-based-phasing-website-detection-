import { useEffect, useState } from "react";
import { api, formatTime } from "../api.js";
import { ErrorBox, Icon, PageHeader, ResultView, RiskBadge, Spinner, Verdict } from "../components.jsx";

const PAGE = 25;

function Detail({ id }) {
  const [item, setItem] = useState(null);
  const [thresholds, setThresholds] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setItem(null);
    setError("");
    api.historyItem(id).then(setItem).catch((e) => setError(e.message));
    api.info().then((i) => setThresholds(i.url_model?.risk_thresholds ?? null)).catch(() => {});
  }, [id]);

  return (
    <>
      <PageHeader title={`Analysis #${id}`} subtitle={item ? `Analysed ${formatTime(item.created_at)}` : ""}>
        <a className="btn" href="#/history"><Icon name="arrowLeft" /> Back to history</a>
      </PageHeader>
      {error && <ErrorBox>{error}</ErrorBox>}
      {!item && !error && <Spinner label="Loading analysis…" />}
      {item && <ResultView result={item.result} thresholds={thresholds} />}
    </>
  );
}

export default function History({ id }) {
  const [rows, setRows] = useState(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (id) return;
    api.history(PAGE, 0).then((r) => { setRows(r); setMore(r.length === PAGE); }).catch((e) => setError(e.message));
  }, [id]);

  if (id) return <Detail id={id} />;

  async function loadMore() {
    try {
      const r = await api.history(PAGE, rows.length);
      setRows([...rows, ...r]);
      setMore(r.length === PAGE);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <>
      <PageHeader title="Analysis History"
        subtitle="Previously analysed inputs. Query strings and login details are removed before saving." />
      {error && <ErrorBox>{error}</ErrorBox>}
      {!rows && !error && <Spinner label="Loading history…" />}
      {rows && rows.length === 0 && (
        <div className="card empty"><Icon name="clock" size={28} /><p>No saved analyses yet.</p>
          <a className="btn primary" href="#/scan">Scan a URL</a></div>
      )}
      {rows && rows.length > 0 && (
        <div className="card table-card">
          <div className="table-scroll">
          <table className="table">
            <thead>
              <tr><th>Time</th><th>Input</th><th>Module</th><th>Prediction</th><th>Risk</th><th className="num">Score</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} onClick={() => (window.location.hash = `#/history/${r.id}`)} tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && (window.location.hash = `#/history/${r.id}`)}>
                  <td className="nowrap muted">{formatTime(r.created_at)}</td>
                  <td className="url-cell" title={r.input_redacted}>{r.input_redacted}</td>
                  <td className="muted">URL</td>
                  <td><Verdict prediction={r.prediction} /></td>
                  <td><RiskBadge risk={r.risk_category} /></td>
                  <td className="num">{r.score == null ? "–" : r.score.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          {more && <button className="btn load-more" onClick={loadMore}>Load more</button>}
        </div>
      )}
    </>
  );
}
