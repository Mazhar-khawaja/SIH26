import { useEffect, useState } from "react";
import "./System.css";

const API_BASE = "http://127.0.0.1:8000";

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

function System() {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [parsers, setParsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  async function loadSystemData(showLoading = true) {
    if (showLoading) {
      setLoading(true);
    }

    setRefreshing(true);
    setError("");

    try {
      const [healthResponse, statsResponse, parserResponse] =
        await Promise.all([
          fetch(`${API_BASE}/health`),
          fetch(`${API_BASE}/stats`),
          fetch(`${API_BASE}/parsers`),
        ]);

      if (!healthResponse.ok) {
        throw new Error("ULPF health endpoint is unavailable.");
      }

      if (!statsResponse.ok) {
        throw new Error("ULPF statistics endpoint is unavailable.");
      }

      if (!parserResponse.ok) {
        throw new Error("ULPF parser registry is unavailable.");
      }

      const [healthData, statsData, parserData] =
        await Promise.all([
          healthResponse.json(),
          statsResponse.json(),
          parserResponse.json(),
        ]);

      setHealth(healthData);
      setStats(statsData);
      setParsers(
        Array.isArray(parserData?.parsers)
          ? parserData.parsers
          : [],
      );
    } catch (systemError) {
      setError(
        systemError?.message ||
          "Unable to connect to ULPF Core.",
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadSystemData();
  }, []);

  const activeParsers = parsers.filter(
    (parser) => parser.enabled,
  ).length;

  const supportedFormats =
    stats?.supported_formats ||
    stats?.formats ||
    stats?.supported ||
    [];

  const formatList = Array.isArray(supportedFormats)
    ? supportedFormats
    : typeof supportedFormats === "object"
      ? Object.keys(supportedFormats)
      : [];

  const eventCount =
    stats?.total_events ??
    stats?.events_count ??
    stats?.event_count ??
    0;

  const healthStatus =
    health?.status ||
    health?.state ||
    "unknown";

  const isHealthy =
    String(healthStatus).toLowerCase() === "healthy" ||
    String(healthStatus).toLowerCase() === "ok";

  return (
    <section className="system-page">
      <header className="system-header">
        <div>
          <div className="system-kicker-row">
            <span className="system-index">05</span>

            <span className="system-kicker">
              SYSTEM / ULPF CORE RUNTIME
            </span>
          </div>

          <h2>System</h2>

          <p>
            Runtime condition, processing capacity, parser
            registration, and supported event formats reported
            directly by ULPF Core.
          </p>
        </div>

        <div className="system-health-badge">
          <span
            className={`system-health-dot ${
              isHealthy ? "healthy" : ""
            }`}
          />

          <div>
            <span>CORE STATUS</span>

            <strong>
              {loading
                ? "CHECKING"
                : String(healthStatus).toUpperCase()}
            </strong>
          </div>
        </div>
      </header>

      {error && (
        <div className="system-error">
          <span>!</span>

          <div>
            <strong>SYSTEM CONNECTION ERROR</strong>

            <p>{error}</p>
          </div>

          <button
            type="button"
            onClick={() => loadSystemData(false)}
          >
            RETRY
          </button>
        </div>
      )}

      <section className="system-overview">
        <div className="system-metric">
          <span>CORE</span>

          <strong>
            {loading
              ? "—"
              : isHealthy
                ? "ONLINE"
                : "CHECK"}
          </strong>

          <small>ULPF API runtime</small>
        </div>

        <div className="system-metric">
          <span>EVENTS PROCESSED</span>

          <strong>
            {loading ? "—" : formatValue(eventCount)}
          </strong>

          <small>Stored event records</small>
        </div>

        <div className="system-metric">
          <span>ACTIVE PARSERS</span>

          <strong>
            {loading ? "—" : activeParsers}
          </strong>

          <small>Registered processors</small>
        </div>

        <div className="system-metric">
          <span>DEPLOYMENT</span>

          <strong>P1</strong>

          <small>Forensic build</small>
        </div>
      </section>

      <section className="system-runtime">
        <div className="system-section-heading">
          <div>
            <span className="system-panel-index">
              A / 05
            </span>

            <span className="system-panel-kicker">
              RUNTIME TELEMETRY
            </span>

            <h3>ULPF Core</h3>
          </div>

          <button
            type="button"
            className="system-refresh"
            onClick={() => loadSystemData(false)}
            disabled={refreshing}
          >
            {refreshing ? "CHECKING..." : "REFRESH STATUS"}
          </button>
        </div>

        <div className="runtime-grid">
          <div className="runtime-block">
            <span>API ENDPOINT</span>

            <strong>{API_BASE}</strong>

            <small>
              Primary local processing interface
            </small>
          </div>

          <div className="runtime-block">
            <span>HEALTH</span>

            <strong>
              {loading
                ? "CHECKING"
                : String(healthStatus).toUpperCase()}
            </strong>

            <small>
              {health?.message ||
                "Health state reported by ULPF Core"}
            </small>
          </div>

          <div className="runtime-block">
            <span>PROCESSING MODEL</span>

            <strong>LOCAL</strong>

            <small>
              Air-gapped compatible architecture
            </small>
          </div>

          <div className="runtime-block">
            <span>PIPELINE</span>

            <strong>07 STAGES</strong>

            <small>
              Ingest → detect → parse → normalize
            </small>
          </div>
        </div>
      </section>

      <section className="system-formats">
        <div className="system-section-heading">
          <div>
            <span className="system-panel-index">
              B / 05
            </span>

            <span className="system-panel-kicker">
              FORMAT SUPPORT
            </span>

            <h3>Universal Input Surface</h3>
          </div>

          <span className="system-count">
            {formatList.length || "—"} FORMATS
          </span>
        </div>

        <div className="format-grid">
          {formatList.length > 0 ? (
            formatList.map((format, index) => (
              <div
                className="format-card"
                key={`${format}-${index}`}
              >
                <span>
                  {String(index + 1).padStart(2, "0")}
                </span>

                <strong>
                  {String(format).toUpperCase()}
                </strong>

                <small>SUPPORTED</small>
              </div>
            ))
          ) : (
            <div className="system-empty">
              No supported-format data returned by the API.
            </div>
          )}
        </div>
      </section>

      <section className="system-parsers">
        <div className="system-section-heading">
          <div>
            <span className="system-panel-index">
              C / 05
            </span>

            <span className="system-panel-kicker">
              PROCESSOR REGISTRY
            </span>

            <h3>Registered Engines</h3>
          </div>

          <span className="system-count">
            {activeParsers} ACTIVE
          </span>
        </div>

        <div className="system-parser-list">
          {parsers.length > 0 ? (
            parsers.map((parser, index) => (
              <div
                className="system-parser-row"
                key={parser.name || index}
              >
                <span className="system-parser-number">
                  {String(index + 1).padStart(2, "0")}
                </span>

                <strong>
                  {String(
                    parser.name || "UNKNOWN",
                  ).toUpperCase()}
                </strong>

                <span>
                  PRIORITY{" "}
                  {parser.priority ?? "—"}
                </span>

                <span
                  className={
                    parser.enabled
                      ? "parser-enabled"
                      : "parser-disabled"
                  }
                >
                  <i />

                  {parser.enabled
                    ? "ENABLED"
                    : "DISABLED"}
                </span>
              </div>
            ))
          ) : (
            <div className="system-empty">
              No parser registry data returned.
            </div>
          )}
        </div>
      </section>

      <footer className="system-footer">
        <span>ULPF CORE</span>

        <span>LOCAL PROCESSING</span>

        <span>
          {refreshing
            ? "STATUS REFRESH IN PROGRESS"
            : "RUNTIME TELEMETRY ACTIVE"}
        </span>
      </footer>
    </section>
  );
}

export default System;