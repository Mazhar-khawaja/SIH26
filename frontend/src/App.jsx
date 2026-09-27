import { useEffect, useState } from "react";

import ProcessEngine from "./ProcessEngine";
import Events from "./Events";
import Parsers from "./Parsers";
import Intelligence from "./Intelligence";
import System from "./System";

import "./ProcessEngine.css";
import "./App.css";

const NAV_ITEMS = [
  {
    id: "process",
    label: "Process",
    code: "01",
    description: "Event processing",
  },
  {
    id: "events",
    label: "Events",
    code: "02",
    description: "Forensic archive",
  },
  {
    id: "parsers",
    label: "Parsers",
    code: "03",
    description: "Parser registry",
  },
  {
    id: "intelligence",
    label: "Intelligence",
    code: "04",
    description: "Format intelligence",
  },
  {
    id: "system",
    label: "System",
    code: "05",
    description: "Core status",
  },
];

function getInitialTheme() {
  const savedTheme = localStorage.getItem("ulpf-theme");

  if (savedTheme === "light" || savedTheme === "dark") {
    return savedTheme;
  }

  return "dark";
}

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activePage, setActivePage] = useState("process");
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.body.setAttribute("data-theme", theme);

    localStorage.setItem("ulpf-theme", theme);
  }, [theme]);

  function toggleTheme() {
    setTheme((currentTheme) =>
      currentTheme === "dark" ? "light" : "dark"
    );
  }

  function renderPage() {
    switch (activePage) {
      case "process":
        return <ProcessEngine />;

      case "events":
        return <Events />;

      case "parsers":
        return <Parsers />;

      case "intelligence":
        return <Intelligence />;

      case "system":
        return <System />;

      default:
        return <ProcessEngine />;
    }
  }

  return (
    <div
      className={`app-shell ${
        sidebarOpen ? "sidebar-open" : "sidebar-collapsed"
      } theme-${theme}`}
    >
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>

          <div className="brand-copy">
            <strong>ULPF</strong>
            <span>EVENT GENOME</span>
          </div>
        </div>

        <button
          type="button"
          className="sidebar-toggle"
          onClick={() => setSidebarOpen((current) => !current)}
          aria-label={
            sidebarOpen ? "Collapse navigation" : "Expand navigation"
          }
          title={sidebarOpen ? "Collapse navigation" : "Expand navigation"}
        >
          <span>{sidebarOpen ? "‹" : "›"}</span>
        </button>

        <div className="sidebar-section-label">
          <span>NAVIGATION</span>
        </div>

        <nav className="main-navigation" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => {
            const active = activePage === item.id;

            return (
              <button
                type="button"
                key={item.id}
                className={`nav-item ${active ? "active" : ""}`}
                onClick={() => setActivePage(item.id)}
                title={
                  sidebarOpen
                    ? item.description
                    : `${item.code} / ${item.label}`
                }
                aria-current={active ? "page" : undefined}
              >
                <span className="nav-code">{item.code}</span>

                <span className="nav-content">
                  <strong>{item.label}</strong>
                  <small>{item.description}</small>
                </span>

                <span className="nav-indicator" />
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="core-status">
            <span className="core-status-dot" />

            <div>
              <strong>ULPF CORE</strong>
              <span>ONLINE</span>
            </div>
          </div>

          <span className="sidebar-version">P1 / FORENSIC BUILD</span>
        </div>
      </aside>

      <main className="app-main">
        <header className="top-bar">
          <div className="top-bar-location">
            <span className="top-bar-marker" />

            <span>UNIVERSAL LOG PRE-PROCESSING FRAMEWORK</span>
          </div>

          <div className="top-bar-actions">
            <div className="top-bar-meta">
              <span>SIH 2026</span>
              <span className="meta-divider" />
              <span>ULPF / P1</span>
            </div>

            <button
              type="button"
              className="theme-toggle"
              onClick={toggleTheme}
              aria-label={`Switch to ${
                theme === "dark" ? "light" : "dark"
              } mode`}
              title={`Switch to ${
                theme === "dark" ? "light" : "dark"
              } mode`}
            >
              <span className="theme-toggle-track">
                <span className="theme-icon theme-icon-sun">☼</span>
                <span className="theme-icon theme-icon-moon">☾</span>

                <span className="theme-toggle-thumb" />
              </span>

              <span className="theme-toggle-label">
                {theme === "dark" ? "DARK" : "LIGHT"}
              </span>
            </button>
          </div>
        </header>

        <div className="page-content">{renderPage()}</div>

        <footer className="app-footer">
          <span>ULPF // EVENT GENOME</span>
          <span>FORENSIC LOG PRE-PROCESSING SYSTEM</span>
          <span>BUILD P1</span>
        </footer>
      </main>
    </div>
  );
}

export default App;