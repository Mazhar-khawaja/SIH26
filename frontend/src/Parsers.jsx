import { useEffect, useState } from "react";
import "./Parsers.css";

const API_BASE = "/api/v1";

function Parsers() {
  const [parsers, setParsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState(null);
  const [actionStatus, setActionStatus] = useState(null);

  async function loadParsers() {
    setLoading(true);
    setError("");
    setActionStatus(null);

    try {
      const response = await fetch(`${API_BASE}/parsers`);

      if (!response.ok) {
        throw new Error("Unable to retrieve parser registry.");
      }

      const data = await response.json();

      setParsers(Array.isArray(data?.parsers) ? data.parsers : []);
    } catch (loadError) {
      setError(
        loadError?.message ||
          "Unable to connect to the ULPF parser registry.",
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadParsers();
  }, []);

  const toggleParser = async (parser) => {
    if (parser.enabled) {
      if (!window.confirm(`Disable ${parser.name.toUpperCase()} parser?`)) {
        return;
      }
    }

    setActionLoading(parser.name);
    setActionStatus(null);
    setError("");

    try {
      const endpoint = parser.enabled ? "disable" : "enable";
      const response = await fetch(`${API_BASE}/parsers/${parser.name}/${endpoint}`, {
        method: "POST",
      });

      if (!response.ok) {
        let msg = `Failed to ${endpoint} parser.`;
        try {
          const body = await response.json();
          if (body.detail) {
            msg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
          }
        } catch(e) {}
        throw new Error(msg);
      }

      setActionStatus({
        type: "success",
        message: `Successfully ${endpoint}d ${parser.name.toUpperCase()} parser.`
      });

      await loadParsers();
    } catch (err) {
      setActionStatus({
        type: "error",
        message: err.message
      });
    } finally {
      setActionLoading(null);
    }
  };

  const enabledCount = parsers.filter(
    (parser) => parser.enabled,
  ).length;

  return (
    <section className="parsers-page">
      <header className="parsers-header">
        <div>
          <div className="parsers-kicker-row">
            <span className="parsers-index">03</span>
            <span className="parsers-kicker">
              PARSER REGISTRY / ENGINE CONTROL
            </span>
          </div>

          <h2>Parsers</h2>

          <p>
            Inspect the plug-and-play parser architecture used by
            ULPF Core to recognize and process vendor-specific event
            formats.
          </p>
        </div>

        <div className="parser-registry-status">
          <span className="registry-dot" />

          <div>
            <span>REGISTRY STATUS</span>
            <strong>
              {loading ? "SCANNING" : "ONLINE"}
            </strong>
          </div>
        </div>
      </header>

      {error && (
        <div className="parser-error">
          <span>!</span>

          <div>
            <strong>REGISTRY ERROR</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {actionStatus && actionStatus.type === "error" && (
        <div className="parser-error">
          <span>!</span>
          <div>
            <strong>ACTION FAILED</strong>
            <p>{actionStatus.message}</p>
          </div>
        </div>
      )}

      {actionStatus && actionStatus.type === "success" && (
        <div className="parser-success">
          <span>✓</span>
          <div>
            <strong>ACTION SUCCESS</strong>
            <p>{actionStatus.message}</p>
          </div>
        </div>
      )}

      <div className="parser-overview">
        <div className="overview-block">
          <span>REGISTERED PARSERS</span>
          <strong>{loading ? "—" : parsers.length}</strong>
        </div>

        <div className="overview-block">
          <span>ACTIVE PARSERS</span>
          <strong>{loading ? "—" : enabledCount}</strong>
        </div>

        <div className="overview-block">
          <span>ARCHITECTURE</span>
          <strong>PLUG-IN</strong>
        </div>

        <div className="overview-block">
          <span>EXECUTION</span>
          <strong>LOCAL</strong>
        </div>
      </div>

      <section className="parser-registry">
        <div className="parser-section-heading">
          <div>
            <span className="panel-index">A / 03</span>
            <span className="panel-kicker">
              REGISTERED PROCESSORS
            </span>
            <h3>Parser Registry</h3>
          </div>

          <button
            type="button"
            className="parser-refresh"
            onClick={loadParsers}
            disabled={loading}
          >
            {loading ? "READING..." : "REFRESH REGISTRY"}
          </button>
        </div>

        <div className="parser-list">
          {loading ? (
            <div className="parser-empty">
              <span>◌</span>
              <strong>READING PARSER REGISTRY</strong>
            </div>
          ) : parsers.length === 0 ? (
            <div className="parser-empty">
              <span>∅</span>
              <strong>NO PARSERS REGISTERED</strong>
            </div>
          ) : (
            parsers.map((parser, index) => (
              <article
                className={`parser-row ${
                  parser.enabled ? "enabled" : "disabled"
                }`}
                key={parser.name || index}
              >
                <div className="parser-number">
                  {String(index + 1).padStart(2, "0")}
                </div>

                <div className="parser-identity">
                  <span className="parser-type">
                    FORMAT PROCESSOR
                  </span>

                  <h4>
                    {String(parser.name || "UNKNOWN").toUpperCase()}
                  </h4>

                  <span className="parser-description">
                    Universal event format parser
                  </span>
                </div>

                <div className="parser-priority">
                  <span>PRIORITY</span>
                  <strong>
                    {parser.priority ?? "—"}
                  </strong>
                </div>

                <div className="parser-state">
                  <span
                    className={`parser-state-indicator ${
                      parser.enabled ? "active" : "inactive"
                    }`}
                  />

                  <div>
                    <span>STATUS</span>
                    <strong>
                      {parser.enabled ? "ENABLED" : "DISABLED"}
                    </strong>
                  </div>
                </div>

                <div className="parser-contract">
                  <span>CONTRACT</span>
                  <strong>UNIVERSAL EVENT</strong>
                </div>

                <div className="parser-actions">
                  <button
                    type="button"
                    className={`parser-action-btn ${parser.enabled ? "disable-btn" : "enable-btn"}`}
                    onClick={() => toggleParser(parser)}
                    disabled={actionLoading === parser.name || loading}
                  >
                    {actionLoading === parser.name ? "WAIT..." : (parser.enabled ? "DISABLE" : "ENABLE")}
                  </button>
                </div>
              </article>
            ))
          )}
        </div>
      </section>

      <section className="parser-architecture">
        <div>
          <span className="panel-index">B / 03</span>
          <span className="panel-kicker">
            EXECUTION MODEL
          </span>
          <h3>Plug-and-Play Architecture</h3>
        </div>

        <div className="architecture-flow">
          <div>
            <span>01</span>
            <strong>RAW LOG</strong>
          </div>

          <i />

          <div>
            <span>02</span>
            <strong>DETECT</strong>
          </div>

          <i />

          <div>
            <span>03</span>
            <strong>PARSER</strong>
          </div>

          <i />

          <div>
            <span>04</span>
            <strong>NORMALIZE</strong>
          </div>

          <i />

          <div>
            <span>05</span>
            <strong>UNIVERSAL EVENT</strong>
          </div>
        </div>
      </section>
    </section>
  );
}

export default Parsers;