import { useEffect, useState } from "react";
import { api } from "./api.js";
import Dashboard from "./pages/Dashboard.jsx";
import UrlScanner from "./pages/UrlScanner.jsx";
import { WebsiteAnalyzer, MessageAnalyzer } from "./pages/Planned.jsx";
import History from "./pages/History.jsx";
import Settings from "./pages/Settings.jsx";
import { Icon } from "./components.jsx";

const NAV = [
  { path: "dashboard", label: "Dashboard", icon: "grid" },
  { path: "scan", label: "URL Scanner", icon: "link" },
  { path: "website", label: "Website Analyzer", icon: "globe", planned: true },
  { path: "message", label: "Message Analyzer", icon: "message", planned: true },
  { path: "history", label: "Analysis History", icon: "clock" },
  { path: "settings", label: "Model & Settings", icon: "cog" },
];

function useHashRoute() {
  const read = () => (window.location.hash.replace(/^#\/?/, "") || "dashboard").split("/");
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const onChange = () => setRoute(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export default function App() {
  const [page, param] = useHashRoute();
  const [health, setHealth] = useState(null);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, []);
  useEffect(() => setMenuOpen(false), [page, param]);

  let content;
  switch (page) {
    case "scan": content = <UrlScanner />; break;
    case "website": content = <WebsiteAnalyzer />; break;
    case "message": content = <MessageAnalyzer />; break;
    case "history": content = <History id={param} />; break;
    case "settings": content = <Settings />; break;
    default: content = <Dashboard />;
  }

  const status =
    health == null ? { cls: "", text: "Checking…" }
    : health.status !== "ok" ? { cls: "down", text: "Backend offline" }
    : health.url_model_loaded ? { cls: "ok", text: "URL model loaded" }
    : { cls: "warn", text: "Model not trained" };

  return (
    <div className="shell">
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <img src="/favicon.svg" alt="" width="30" height="30" />
          <div>
            <div className="brand-name">PhishGuard AI</div>
            <div className="brand-tag">Detect · Analyze · Explain</div>
          </div>
        </div>
        <nav>
          {NAV.map((n) => (
            <a key={n.path} href={`#/${n.path}`} className={page === n.path || (page === "" && n.path === "dashboard") ? "active" : ""}>
              <Icon name={n.icon} />
              <span>{n.label}</span>
              {n.planned && <span className="pill-planned">Planned</span>}
            </a>
          ))}
        </nav>
        <div className={`server-status ${status.cls}`}>
          <span className="dot" /> {status.text}
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setMenuOpen((o) => !o)} aria-label="Toggle navigation">
            <Icon name="menu" />
          </button>
          <span className="topbar-title">PhishGuard AI</span>
        </header>
        <main className="content">{content}</main>
      </div>
      {menuOpen && <div className="scrim" onClick={() => setMenuOpen(false)} />}
    </div>
  );
}
