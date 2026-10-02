import { useEffect, useMemo, useState } from "react";
import "./ProcessEngine.css";

const API_BASE = "/api/v1";

const DEFAULT_RAW_LOG =
  "<134>Sep 14 21:45:32 FIREWALL01 DENY src=10.10.20.15 dst=8.8.8.8 sport=51524 dport=443 proto=TCP severity=HIGH";

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }

  if (typeof value === "string" && value.trim() === "") {
    return "N/A";
  }

  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "N/A";
    }
  }

  return String(value);
}

function getEventPayload(response) {
  if (!response || typeof response !== "object") {
    return {};
  }

  if (
    response.event &&
    typeof response.event === "object"
  ) {
    return {
      ...response.event,
      integrity: response.integrity ?? response.event.integrity,
      quality: response.quality ?? response.event.quality,
      format: response.format ?? response.event.format,
    };
  }

  return response;
}

function getConfidence(event) {
  let val = null;
  if (event?.confidence !== undefined && event.confidence !== null) {
    val = Number(event.confidence);
  } else if (event?.format?.confidence !== undefined && event.format.confidence !== null) {
    val = Number(event.format.confidence);
  }
  
  if (val === null || isNaN(val)) return null;
  
  if (val <= 1.0) {
    return Math.round(val * 100);
  }
  return Math.round(val);
}

function getQuality(event) {
  if (event?.quality?.quality_score !== undefined) {
    return event.quality.quality_score;
  }

  if (event?.quality_score !== undefined) {
    return event.quality_score;
  }

  return null;
}

function getFieldCount(event) {
  if (
    event?.extracted_data &&
    typeof event.extracted_data === "object"
  ) {
    return Object.keys(event.extracted_data).length;
  }

  const fields = [
    event?.event_id,
    event?.timestamp,
    event?.source,
    event?.source_ip,
    event?.source_port,
    event?.destination,
    event?.destination_ip,
    event?.destination_port,
    event?.protocol,
    event?.event_type,
    event?.action,
    event?.severity,
    event?.parser,
    event?.format,
    event?.parse_status,
  ];

  return fields.filter(
    (value) =>
      value !== null &&
      value !== undefined &&
      value !== ""
  ).length;
}

function getParser(event) {
  if (typeof event?.parser === "string") {
    return event.parser;
  }

  if (
    event?.parser &&
    typeof event.parser === "object"
  ) {
    return (
      event.parser.name ||
      event.parser.parser_name ||
      "N/A"
    );
  }

  return "N/A";
}

function getFormat(event) {
  if (typeof event?.format === "string") {
    return event.format;
  }

  if (
    event?.format &&
    typeof event.format === "object"
  ) {
    return event.format.format || "N/A";
  }

  return "N/A";
}

function ProcessEngine() {
  const [rawLog, setRawLog] = useState(DEFAULT_RAW_LOG);
  const [processing, setProcessing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [showRaw, setShowRaw] = useState(false);

  const processEvent = async () => {
    if (!rawLog.trim() || processing) {
      return;
    }

    setProcessing(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/events`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            log: rawLog,
          }),
        }
      );

      if (!response.ok) {
        let message = `Request failed with status ${response.status}`;

        try {
          const errorBody = await response.json();

          if (errorBody?.detail) {
            message =
              typeof errorBody.detail === "string"
                ? errorBody.detail
                : JSON.stringify(errorBody.detail);
          }
        } catch {
          // Keep default message.
        }

        throw new Error(message);
      }

      const responseData = await response.json();

      setResult(getEventPayload(responseData));
      setProcessing(false);
    } catch (requestError) {
      console.error(requestError);

      setError(
        requestError?.message ||
          "Unable to process the event."
      );

      setProcessing(false);
    }
  };

  const clearProcessing = () => {
    setRawLog("");
    setResult(null);
    setError("");
    setProcessing(false);
    setShowRaw(false);
  };

  const loadExample = () => {
    setRawLog(DEFAULT_RAW_LOG);
    setResult(null);
    setError("");
    setShowRaw(false);
  };

  const event = result || {};

  const parser = getParser(event);
  const format = getFormat(event);
  const quality = getQuality(event);
  const confidence = getConfidence(event);
  const fieldCount = getFieldCount(event);

  const currentActivity = processing
    ? "PROCESSING SIGNAL"
    : result
    ? "COMPLETE"
    : error
    ? "FAILED"
    : "IDLE";

  const schemaGroups = useMemo(
    () => [
      {
        id: "identity",
        title: "IDENTITY",
        description: "Event identity and temporal context",
        fields: [
          ["event_id", event.event_id],
          ["timestamp", event.timestamp],
          ["event_type", event.event_type],
        ],
      },
      {
        id: "source",
        title: "SOURCE",
        description: "Origin of the observed event",
        fields: [
          ["source", event.source],
          ["source_type", event.source_type],
          ["source_ip", event.source_ip],
          ["source_port", event.source_port],
        ],
      },
      {
        id: "destination",
        title: "DESTINATION",
        description: "Target of the observed event",
        fields: [
          ["destination", event.destination],
          ["destination_ip", event.destination_ip],
          ["destination_port", event.destination_port],
        ],
      },
      {
        id: "security",
        title: "NETWORK / SECURITY",
        description: "Security and network semantics",
        fields: [
          ["protocol", event.protocol],
          ["action", event.action],
          ["severity", event.severity],
        ],
      },
      {
        id: "processing",
        title: "PROCESSING",
        description: "ULPF normalization metadata",
        fields: [
          ["parser", parser],
          ["format", format],
          ["parse_status", event.parse_status],
          [
            "quality_status",
            event.quality_status ||
              event.quality?.status,
          ],
          ["quality_score", quality],
        ],
      },
    ],
    [event, parser, format, quality]
  );

  return (
    <main className="process-engine">

      {/* =====================================================
          PROCESS HEADER
          ===================================================== */}

      <section className="analysis-header">

        <div className="analysis-intro">

          <div className="analysis-kicker">
            ULPF // EVENT GENOME
          </div>

          <div className="analysis-title-row">

            <div>
              <div className="analysis-index">
                01 / PROCESS ENGINE
              </div>

              <h1>
                {result
                  ? "Event Reconstructed"
                  : processing
                  ? "Processing Event"
                  : "Analyze Raw Event"}
              </h1>
            </div>

            <div
              className={`analysis-state ${
                processing
                  ? "is-processing"
                  : result
                  ? "is-complete"
                  : error
                  ? "is-error"
                  : "is-ready"
              }`}
            >
              <span className="state-dot" />

              <span>
                {processing
                  ? "ANALYZING"
                  : result
                  ? "COMPLETE"
                  : error
                  ? "ERROR"
                  : "READY"}
              </span>
            </div>

          </div>

          <p>
            Transform heterogeneous vendor logs into a
            common Universal Event Schema while preserving
            the original security evidence for forensic
            traceability.
          </p>

        </div>

        <div className="analysis-progress">

          <div
            className={`progress-ring ${processing ? "is-processing" : ""}`}
            style={{
              "--progress-angle": processing ? "360deg" : result ? "360deg" : "0deg",
            }}
          >
            <div className="progress-ring-core">

              <strong>
                {processing
                  ? "◌"
                  : result
                  ? (confidence !== null ? `${Math.round(confidence)}%` : "✓")
                  : error
                  ? "!"
                  : "—"}
              </strong>

              <span>
                {result
                  ? "COMPLETE"
                  : processing
                  ? "PROCESSING"
                  : error
                  ? "FAILED"
                  : "IDLE"}
              </span>

            </div>
          </div>

          <div className="progress-context">

            <span>REQUEST STATE</span>

            <strong>
              {currentActivity}
            </strong>

          </div>

        </div>

      </section>


      {/* =====================================================
          INPUT / TELEMETRY
          ===================================================== */}

      <section className="analysis-workspace">

        <div className="raw-panel">

          <div className="panel-heading">

            <div className="panel-heading-main">

              <span className="panel-index">
                00
              </span>

              <div>
                <span className="panel-kicker">
                  RAW SIGNAL
                </span>

                <h2>
                  Event Input
                </h2>
              </div>

            </div>

            <div className="ingest-state">
              <span />
              UNIVERSAL INGEST
            </div>

          </div>

          <div className="editor-shell">

            <div className="editor-header">

              <span className="editor-title">
                SIGNAL BUFFER
              </span>

              <span>
                ULPF://RAW/EVIDENCE
              </span>

            </div>

            <div className="editor-body">

              <div className="editor-line-number">
                01
              </div>

              <textarea
                className="raw-log-input"
                value={rawLog}
                onChange={(event) =>
                  setRawLog(event.target.value)
                }
                disabled={processing}
                spellCheck="false"
                aria-label="Raw security log"
                placeholder="Paste a raw security event..."
              />

            </div>

            <div className="editor-footer">

              <span>
                {rawLog.length} CHARACTERS
              </span>

              <span>
                ORIGINAL SIGNAL
              </span>

            </div>

          </div>

          <div className="input-actions">

            <button
              type="button"
              className="secondary-action"
              onClick={clearProcessing}
              disabled={
                processing ||
                (!rawLog &&
                  !result &&
                  !error)
              }
            >
              RESET
            </button>

            <button
              type="button"
              className="secondary-action"
              onClick={loadExample}
              disabled={processing}
            >
              LOAD EXAMPLE
            </button>

            <button
              type="button"
              className="primary-action"
              onClick={processEvent}
              disabled={
                processing ||
                !rawLog.trim()
              }
            >
              {processing
                ? "PROCESSING SIGNAL..."
                : "PROCESS RAW SIGNAL"}
            </button>

          </div>

          {error && (
            <div className="processing-error">

              <strong>
                PROCESSING ERROR
              </strong>

              <span>
                {error}
              </span>

            </div>
          )}

        </div>


        {/* ===================================================
            TELEMETRY
            =================================================== */}

        <aside className="telemetry-panel">

          <div className="panel-heading">

            <div className="panel-heading-main">

              <span className="panel-index">
                01
              </span>

              <div>
                <span className="panel-kicker">
                  EVENT TELEMETRY
                </span>

                <h2>
                  Processing Result
                </h2>
              </div>

            </div>

          </div>

          {!result && !processing && (
            <div className="telemetry-empty">

              <span className="telemetry-symbol">
                ○
              </span>

              <strong>
                NO EVENT PROCESSED
              </strong>

              <p>
                Process a raw security signal to
                generate its Universal Event Schema.
              </p>

            </div>
          )}

          {processing && (
            <div className="telemetry-processing">

              <span className="processing-spinner">
                ◌
              </span>

              <strong>
                ANALYZING SIGNAL
              </strong>

              <p>
                Detecting format, extracting fields
                and normalizing the event.
              </p>

            </div>
          )}

          {result && (
            <div className="telemetry-content">

              <div className="telemetry-primary">

                <span>EVENT ID</span>

                <strong>
                  {formatValue(event.event_id)}
                </strong>

              </div>

              <div className="telemetry-grid">

                <TelemetryCell
                  label="FORMAT"
                  value={format}
                />

                <TelemetryCell
                  label="PARSER"
                  value={parser}
                />

                <TelemetryCell
                  label="FIELDS"
                  value={`${fieldCount} DETECTED`}
                />

                <TelemetryCell
                  label="QUALITY"
                  value={
                    quality !== null
                      ? `${quality}%`
                      : "N/A"
                  }
                />

                <TelemetryCell
                  label="CONFIDENCE"
                  value={
                    confidence !== null
                      ? `${confidence}%`
                      : "N/A"
                  }
                />

                <TelemetryCell
                  label="INTEGRITY"
                  value={
                    event?.integrity?.verified
                      ? "VERIFIED"
                      : "AVAILABLE"
                  }
                />

              </div>

            </div>
          )}

        </aside>

      </section>


      {/* =====================================================
          UNIVERSAL EVENT SCHEMA
          ===================================================== */}

      <section className="universal-schema-section">

        <div className="schema-section-header">

          <div className="schema-heading-left">

            <div className="schema-index">
              02
            </div>

            <div>

              <span className="schema-kicker">
                ULPF NORMALIZATION CONTRACT
              </span>

              <h2>
                Universal Event Schema
              </h2>

              <p>
                The standardized event representation
                produced from any supported vendor or
                log format.
              </p>

            </div>

          </div>

          <div className="schema-status">

            <span
              className={
                result
                  ? "schema-status-dot ready"
                  : "schema-status-dot"
              }
            />

            <span>
              {result
                ? "NORMALIZED EVENT"
                : "AWAITING EVENT"}
            </span>

          </div>

        </div>


        {result ? (
          <>

            <div className="schema-conversion-bar">

              <div className="schema-node">
                <span className="schema-node-label">
                  INPUT
                </span>

                <strong>
                  {format.toUpperCase()}
                </strong>

                <small>
                  Vendor-specific event
                </small>
              </div>

              <div className="schema-connector">
                <span />
                <strong>
                  ULPF
                </strong>
                <span />
              </div>

              <div className="schema-node schema-node-primary">

                <span className="schema-node-label">
                  OUTPUT
                </span>

                <strong>
                  UNIVERSAL EVENT
                </strong>

                <small>
                  Normalized representation
                </small>

              </div>

            </div>


            <div className="schema-groups">

              {schemaGroups.map((group) => (

                <section
                  className="schema-group"
                  key={group.id}
                >

                  <div className="schema-group-header">

                    <div>

                      <span>
                        {group.title}
                      </span>

                      <small>
                        {group.description}
                      </small>

                    </div>

                  </div>

                  <div className="schema-fields">

                    {group.fields.map(
                      ([key, value]) => (

                        <div
                          className="schema-field"
                          key={key}
                        >

                          <span className="schema-field-key">
                            {key}
                          </span>

                          <strong
                            title={formatValue(value)}
                          >
                            {formatValue(value)}
                          </strong>

                        </div>

                      )
                    )}

                  </div>

                </section>

              ))}

            </div>


            <div className="schema-footer">

              <div>
                <span>RAW EVENT</span>
                <strong>PRESERVED</strong>
              </div>

              <div>
                <span>TRACEABILITY</span>
                <strong>LINKED</strong>
              </div>

              <div>
                <span>OUTPUT</span>
                <strong>JSON READY</strong>
              </div>

              <div>
                <span>FORMAT</span>
                <strong>
                  {format.toUpperCase()}
                </strong>
              </div>

            </div>

          </>
        ) : (
          <div className="schema-empty">

            <div className="schema-empty-mark">
              {"{ }"}
            </div>

            <strong>
              UNIVERSAL EVENT SCHEMA
            </strong>

            <p>
              Process a raw event to populate the
              normalized ULPF schema.
            </p>

          </div>
        )}

      </section>


      {/* =====================================================
          FORENSIC OUTPUT
          ===================================================== */}

      {result && (
        <section className="forensic-result">

          <div className="forensic-header">

            <div>

              <span>
                03 / FORENSIC RESULT
              </span>

              <h2>
                Event Genome
              </h2>

            </div>

            <button
              type="button"
              className="raw-toggle"
              onClick={() =>
                setShowRaw((current) => !current)
              }
            >
              {showRaw
                ? "HIDE RAW EVIDENCE"
                : "VIEW RAW EVIDENCE"}
            </button>

          </div>


          {showRaw && (
            <div className="forensic-raw">

              <div className="forensic-raw-label">
                ORIGINAL RAW EVENT
              </div>

              <pre>
                {formatValue(
                  event.raw_event || rawLog
                )}
              </pre>

            </div>
          )}


          <div className="forensic-grid">

            <ForensicCell
              label="EVENT ID"
              value={event.event_id}
            />

            <ForensicCell
              label="PARSER"
              value={parser}
            />

            <ForensicCell
              label="FORMAT"
              value={format}
            />

            <ForensicCell
              label="PARSE STATUS"
              value={event.parse_status}
            />

            <ForensicCell
              label="QUALITY"
              value={
                quality !== null
                  ? `${quality}%`
                  : "—"
              }
            />

            <ForensicCell
              label="RAW HASH"
              value={
                event.raw_hash ||
                event.integrity?.sha256
              }
            />

            <ForensicCell
              label="CHAIN HASH"
              value={
                event.chain_hash ||
                event.integrity?.chain_hash
              }
            />

            <ForensicCell
              label="CHAIN STATUS"
              value={
                event.integrity?.chain_verified
                  ? "VERIFIED"
                  : "—"
              }
            />

          </div>

        </section>
      )}

    </main>
  );
}


function TelemetryCell({ label, value }) {
  return (
    <div className="telemetry-cell">

      <span>
        {label}
      </span>

      <strong title={formatValue(value)}>
        {formatValue(value)}
      </strong>

    </div>
  );
}


function ForensicCell({ label, value }) {
  return (
    <div className="forensic-cell">

      <span>
        {label}
      </span>

      <strong title={formatValue(value)}>
        {formatValue(value)}
      </strong>

    </div>
  );
}


export default ProcessEngine;