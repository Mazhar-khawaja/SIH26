import { useState } from "react";
import "./Intelligence.css";

const API_BASE = "http://127.0.0.1:8000";

const SAMPLES = {
  syslog:
    "<134>Sep 14 21:45:32 FIREWALL01 DENY src=10.10.20.15 dst=8.8.8.8 sport=51524 dport=443 proto=TCP severity=HIGH",

  json: JSON.stringify(
    {
      timestamp: "2026-09-14T21:45:32Z",
      source: "FIREWALL01",
      source_ip: "10.10.20.15",
      destination_ip: "8.8.8.8",
      destination_port: 443,
      protocol: "TCP",
      action: "DENY",
      severity: "HIGH",
    },
    null,
    2,
  ),

  cef: 'CEF:0|Palo Alto Networks|PA Firewall|10.2|TRAFFIC|Traffic Denied|10|src=10.10.20.15 dst=8.8.8.8 spt=51524 dpt=443 proto=TCP act=DENY',

  leef: 'LEEF:2.0|IBM|QRadar|1.0|NetworkEvent|src=10.10.20.15\tdst=8.8.8.8\tspt=51524\tdpt=443\tproto=TCP\taction=DENY',

  xml: `<event>
  <timestamp>2026-09-14T21:45:32Z</timestamp>
  <source>FIREWALL01</source>
  <source_ip>10.10.20.15</source_ip>
  <destination_ip>8.8.8.8</destination_ip>
  <destination_port>443</destination_port>
  <protocol>TCP</protocol>
  <action>DENY</action>
  <severity>HIGH</severity>
</event>`,

  csv: `timestamp,source,source_ip,destination_ip,destination_port,protocol,action,severity
2026-09-14T21:45:32Z,FIREWALL01,10.10.20.15,8.8.8.8,443,TCP,DENY,HIGH`,

  unknown:
    "DEVICE=FIREWALL01 ## EVENT_SEQUENCE 88421 ## SRC_NODE 10.10.20.15 ## TARGET_NODE 8.8.8.8 ## OPERATION_BLOCKED ## RISK_VECTOR=CRITICAL ## SENSOR_X9",
};

function formatLabel(value) {
  if (!value) {
    return "UNKNOWN";
  }

  return String(value).toUpperCase();
}

function confidencePercent(value) {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Math.max(0, Math.min(100, numeric * 100));
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

function Intelligence() {
  const [rawLog, setRawLog] = useState(SAMPLES.unknown);
  const [result, setResult] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState("");

  async function analyzeSignal() {
    if (!rawLog.trim()) {
      setError("Enter a raw event signal before analysis.");
      return;
    }

    setProcessing(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/events`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          raw_event: rawLog,
          log: rawLog,
          raw_log: rawLog,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            "ULPF format intelligence analysis failed.",
        );
      }

      setResult(data);
    } catch (analysisError) {
      setError(
        analysisError?.message ||
          "Unable to connect to ULPF Core.",
      );
    } finally {
      setProcessing(false);
    }
  }

  function loadSample(type) {
    setRawLog(SAMPLES[type]);
    setResult(null);
    setError("");
  }

  const format = result?.format || {};
  const detectedFormat =
    format.format ||
    result?.event?.format ||
    "unknown";

  const confidence = confidencePercent(
    format.confidence ??
      result?.event?.quality_score / 100 ??
      0,
  );

  const supported =
    format.supported === true ||
    String(format.status || "").toLowerCase() === "supported";

  const candidates = Array.isArray(format.candidates)
    ? format.candidates
    : [];

  const extractedData =
    format.extracted_data ||
    result?.event?.extracted_data ||
    {};

  const fieldMappings =
    format.field_mapping_suggestions || {};

  return (
    <section className="intelligence-page">
      <header className="intelligence-header">
        <div>
          <div className="intelligence-kicker-row">
            <span className="intelligence-index">04</span>

            <span className="intelligence-kicker">
              FORMAT INTELLIGENCE / UNKNOWN SIGNAL ANALYSIS
            </span>
          </div>

          <h2>Intelligence</h2>

          <p>
            Determine the structure of an incoming event before
            normalization. ULPF evaluates parser recognition,
            format confidence, extracted signals, and field
            mapping evidence.
          </p>
        </div>

        <div className="intelligence-status">
          <span
            className={`intelligence-status-dot ${
              result ? "active" : ""
            }`}
          />

          <div>
            <span>ANALYSIS ENGINE</span>
            <strong>
              {processing
                ? "ANALYZING"
                : result
                  ? "ANALYSIS READY"
                  : "STANDBY"}
            </strong>
          </div>
        </div>
      </header>

      <section className="intelligence-workspace">
        <div className="intelligence-input-panel">
          <div className="intelligence-panel-heading">
            <div>
              <span className="intelligence-panel-index">
                A / 04
              </span>

              <span className="intelligence-panel-kicker">
                INPUT SIGNAL
              </span>

              <h3>Unknown Format Detector</h3>
            </div>

            <span className="intelligence-live-tag">
              ULPF CORE
            </span>
          </div>

          <div className="sample-selector">
            <span>LOAD TEST SIGNAL</span>

            <div>
              {Object.keys(SAMPLES).map((sample) => (
                <button
                  type="button"
                  key={sample}
                  onClick={() => loadSample(sample)}
                >
                  {sample.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <textarea
            className="intelligence-editor"
            value={rawLog}
            onChange={(event) => {
              setRawLog(event.target.value);
              setResult(null);
              setError("");
            }}
            spellCheck="false"
            placeholder="Paste an incoming vendor log signal..."
          />

          <div className="intelligence-input-footer">
            <span>
              SIGNAL SIZE / {new Blob([rawLog]).size} BYTES
            </span>

            <button
              type="button"
              className="analyze-button"
              onClick={analyzeSignal}
              disabled={processing}
            >
              {processing
                ? "ANALYZING SIGNAL..."
                : "ANALYZE FORMAT"}
            </button>
          </div>

          {error && (
            <div className="intelligence-error">
              <span>!</span>

              <div>
                <strong>ANALYSIS ERROR</strong>
                <p>{error}</p>
              </div>
            </div>
          )}
        </div>

        <div className="intelligence-result-panel">
          <div className="intelligence-panel-heading">
            <div>
              <span className="intelligence-panel-index">
                B / 04
              </span>

              <span className="intelligence-panel-kicker">
                DETECTION RESULT
              </span>

              <h3>Format Analysis</h3>
            </div>

            <span
              className={`detection-badge ${
                supported ? "supported" : "unknown"
              }`}
            >
              {result
                ? supported
                  ? "SUPPORTED"
                  : "UNKNOWN"
                : "WAITING"}
            </span>
          </div>

          {!result ? (
            <div className="intelligence-empty">
              <div className="empty-symbol">◎</div>

              <strong>NO SIGNAL ANALYZED</strong>

              <p>
                Submit a raw event to inspect format recognition,
                confidence, parser candidates, and structural
                evidence.
              </p>
            </div>
          ) : (
            <>
              <div className="detection-core">
                <div className="confidence-ring">
                  <div>
                    <strong>
                      {Math.round(confidence)}
                    </strong>

                    <span>%</span>
                  </div>
                </div>

                <div className="detection-summary">
                  <span>DETECTED FORMAT</span>

                  <strong>
                    {formatLabel(detectedFormat)}
                  </strong>

                  <p>
                    {format.message ||
                      format.reason ||
                      "ULPF completed format analysis."}
                  </p>
                </div>
              </div>

              <div className="intelligence-facts">
                <div>
                  <span>STATUS</span>
                  <strong>
                    {formatLabel(format.status || "ANALYZED")}
                  </strong>
                </div>

                <div>
                  <span>PARSER</span>
                  <strong>
                    {formatLabel(
                      result?.event?.parser ||
                        "NO PARSER",
                    )}
                  </strong>
                </div>

                <div>
                  <span>CONFIDENCE</span>
                  <strong>
                    {Math.round(confidence)}%
                  </strong>
                </div>

                <div>
                  <span>SUPPORTED</span>
                  <strong>
                    {supported ? "YES" : "NO"}
                  </strong>
                </div>
              </div>

              <div className="intelligence-reason">
                <span>DETECTION REASON</span>

                <p>
                  {format.reason ||
                    format.message ||
                    "No additional explanation supplied by the parser engine."}
                </p>
              </div>

              {candidates.length > 0 && (
                <div className="intelligence-section">
                  <div className="intelligence-section-title">
                    <span>01</span>
                    <strong>FORMAT CANDIDATES</strong>
                  </div>

                  <div className="candidate-list">
                    {candidates.map((candidate, index) => (
                      <div
                        className="candidate-row"
                        key={`${candidate.format || "candidate"}-${index}`}
                      >
                        <span>
                          {String(index + 1).padStart(2, "0")}
                        </span>

                        <strong>
                          {formatLabel(candidate.format)}
                        </strong>

                        <div className="candidate-confidence">
                          <i
                            style={{
                              width: `${confidencePercent(
                                candidate.confidence,
                              )}%`,
                            }}
                          />

                          <span>
                            {Math.round(
                              confidencePercent(
                                candidate.confidence,
                              ),
                            )}
                            %
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {Object.keys(extractedData).length > 0 && (
                <div className="intelligence-section">
                  <div className="intelligence-section-title">
                    <span>02</span>
                    <strong>EXTRACTED SIGNALS</strong>
                  </div>

                  <div className="signal-grid">
                    {Object.entries(extractedData)
                      .slice(0, 12)
                      .map(([key, value]) => (
                        <div
                          className="signal-cell"
                          key={key}
                        >
                          <span>{key}</span>
                          <strong>
                            {displayValue(value)}
                          </strong>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {Object.keys(fieldMappings).length > 0 && (
                <div className="intelligence-section">
                  <div className="intelligence-section-title">
                    <span>03</span>
                    <strong>FIELD MAPPING SUGGESTIONS</strong>
                  </div>

                  <div className="mapping-list">
                    {Object.entries(fieldMappings).map(
                      ([key, value]) => (
                        <div
                          className="mapping-row"
                          key={key}
                        >
                          <span>{key}</span>
                          <strong>
                            {displayValue(value)}
                          </strong>
                        </div>
                      ),
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </section>

      <section className="intelligence-method">
        <div>
          <span className="intelligence-panel-index">
            C / 04
          </span>

          <span className="intelligence-panel-kicker">
            DETECTION MODEL
          </span>

          <h3>Explainable Format Intelligence</h3>
        </div>

        <div className="intelligence-method-flow">
          <div>
            <span>01</span>
            <strong>STRUCTURE</strong>
            <small>
              Inspect syntax and event shape
            </small>
          </div>

          <i />

          <div>
            <span>02</span>
            <strong>CANDIDATES</strong>
            <small>
              Compare available format processors
            </small>
          </div>

          <i />

          <div>
            <span>03</span>
            <strong>CONFIDENCE</strong>
            <small>
              Quantify parser recognition
            </small>
          </div>

          <i />

          <div>
            <span>04</span>
            <strong>EXPLAIN</strong>
            <small>
              Return reason and mapping evidence
            </small>
          </div>
        </div>
      </section>
    </section>
  );
}

export default Intelligence;