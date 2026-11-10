async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  } catch {
    throw new Error("Cannot reach the PhishGuard server. Is the backend running?");
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON response */
  }
  if (!res.ok) {
    const detail = body?.detail;
    const msg = Array.isArray(detail) ? detail.map((d) => d.msg).join("; ") : detail;
    throw new Error(msg || `Request failed (${res.status}).`);
  }
  return body;
}

export const api = {
  health: () => request("/api/health"),
  stats: () => request("/api/stats"),
  info: () => request("/api/info"),
  history: (limit = 50, offset = 0) => request(`/api/history?limit=${limit}&offset=${offset}`),
  historyItem: (id) => request(`/api/history/${id}`),
  analyzeUrl: (url, saveToHistory = true) =>
    request("/api/url/analyze", { method: "POST", body: JSON.stringify({ url, save_to_history: saveToHistory }) }),
};

export function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function pct(v, digits = 1) {
  return v == null ? "–" : `${(v * 100).toFixed(digits)}%`;
}
