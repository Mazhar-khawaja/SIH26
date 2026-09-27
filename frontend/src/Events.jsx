import { useEffect, useMemo, useState } from "react";
import "./Events.css";

const API_BASE = "/api/v1";

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (typeof value === "object") {
    if (Array.isArray(value)) {
      return value.join(", ");
    }

    return (
      value.name ||
      value.ip ||
      value.value ||
      JSON.stringify(value)
    );
  }

  return String(value);
}

function getEventList(data) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.events)) {
    return data.events;
  }

  if (Array.isArray(data?.data)) {
    return data.data;
  }

  return [];
}

function getQuality(event) {
  if (event?.quality_score !== undefined) {
    return Number(event.quality_score);
  }

  if (event?.quality?.quality_score !== undefined) {
    return Number(event.quality.quality_score);
  }

  return null;
}

function getFormat(event) {
  return (
    event?.format ||
    event?.format_analysis?.format ||
    event?.parser ||
    "UNKNOWN"
  );
}

function getParser(event) {
  return event?.parser || "—";
}

function getIntegrity(event) {
  if (
    event?.integrity?.verified ||
    event?.integrity?.chain_verified ||
    event?.chain_hash
  ) {
    return "VERIFIED";
  }

  return "—";
}

function getSource(event) {
  if (event?.source_ip) {
    return `${event.source_ip}${
      event.source_port ? `:${event.source_port}` : ""
    }`;
  }

  return displayValue(event?.source);
}

function getDestination(event) {
  if (event?.destination_ip) {
    return `${event.destination_ip}${
      event.destination_port ? `:${event.destination_port}` : ""
    }`;
  }

  return displayValue(event?.destination);
}

function Events() {
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filterFormat, setFilterFormat] = useState("ALL");

  async function loadEvents() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/events`);

      if (!response.ok) {
        throw new Error("Unable to retrieve events from ULPF Core.");
      }

      const data = await response.json();
      const eventList = getEventList(data);

      setEvents(eventList);

      if (eventList.length > 0) {
        setSelectedEvent((current) => current || eventList[0]);
      } else {
        setSelectedEvent(null);
      }
    } catch (loadError) {
      setError(
        loadError?.message ||
          "Unable to connect to the ULPF event store.",
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadEvents();
  }, []);

  const formats = useMemo(() => {
    const unique = new Set();

    events.forEach((event) => {
      unique.add(String(getFormat(event)).toUpperCase());
    });

    return ["ALL", ...Array.from(unique)];
  }, [events]);

  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();

    return events.filter((event) => {
      const format = String(getFormat(event)).toUpperCase();

      const matchesFormat =
        filterFormat === "ALL" || format === filterFormat;

      if (!matchesFormat) {
        return false;
      }

      if (!query) {
        return true;
      }

      const searchable = [
        event?.event_id,
        event?.source,
        event?.source_ip,
        event?.destination,
        event?.destination_ip,
        event?.action,
        event?.severity,
        event?.parser,
        event?.format,
        event?.raw_event,
      ]
        .map(displayValue)
        .join(" ")
        .toLowerCase();

      return searchable.includes(query);
    });
  }, [events, search, filterFormat]);

  function selectEvent(event) {
    setSelectedEvent(event);
  }

  return (
    <section className="events-page">
      <header className="events-header">
        <div>
          <div className="events-kicker-row">
            <span className="events-index">02</span>
            <span className="events-kicker">
              FORENSIC EVENT ARCHIVE
            </span>
          </div>

          <h2>Events</h2>

          <p>
            Inspect normalized security events while retaining the
            original evidence, parser context, quality information,
            and integrity chain.
          </p>
        </div>

        <div className="events-header-status">
          <span className="archive-status-dot" />
          <div>
            <span>EVENT STORE</span>
            <strong>
              {loading ? "SCANNING" : `${events.length} EVENTS`}
            </strong>
          </div>
        </div>
      </header>

      <div className="events-toolbar">
        <div className="events-search">
          <span>⌕</span>

          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search event ID, source, destination, action..."
          />
        </div>

        <div className="format-filter">
          <span>FORMAT</span>

          <select
            value={filterFormat}
            onChange={(event) => setFilterFormat(event.target.value)}
          >
            {formats.map((format) => (
              <option key={format} value={format}>
                {format}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          className="refresh-events"
          onClick={loadEvents}
          disabled={loading}
        >
          {loading ? "SCANNING..." : "REFRESH ARCHIVE"}
        </button>
      </div>

      {error && (
        <div className="events-error">
          <span>!</span>
          <div>
            <strong>EVENT STORE ERROR</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      <div className="events-layout">
        <section className="events-table-panel">
          <div className="events-panel-heading">
            <div>
              <span className="panel-index">A / 02</span>
              <span className="panel-kicker">EVENT STREAM</span>
              <h3>Normalized Events</h3>
            </div>

            <span className="panel-count">
              {filteredEvents.length} MATCHING
            </span>
          </div>

          <div className="events-table-wrap">
            {loading ? (
              <div className="events-empty">
                <span className="empty-marker">◌</span>
                <strong>READING EVENT ARCHIVE</strong>
                <p>Retrieving normalized events from ULPF Core.</p>
              </div>
            ) : filteredEvents.length === 0 ? (
              <div className="events-empty">
                <span className="empty-marker">∅</span>
                <strong>NO EVENTS FOUND</strong>
                <p>
                  No stored events match the current search and
                  format filter.
                </p>
              </div>
            ) : (
              <table className="events-table">
                <thead>
                  <tr>
                    <th>EVENT ID</th>
                    <th>FORMAT</th>
                    <th>SOURCE</th>
                    <th>ACTION</th>
                    <th>SEVERITY</th>
                    <th>QUALITY</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredEvents.map((event, index) => {
                    const isSelected =
                      selectedEvent?.event_id === event?.event_id;

                    const quality = getQuality(event);

                    return (
                      <tr
                        key={
                          event?.event_id ||
                          `${event?.created_at || "event"}-${index}`
                        }
                        className={isSelected ? "selected" : ""}
                        onClick={() => selectEvent(event)}
                      >
                        <td>
                          <span className="event-id">
                            {displayValue(event?.event_id)}
                          </span>
                        </td>

                        <td>
                          <span className="format-tag">
                            {String(getFormat(event)).toUpperCase()}
                          </span>
                        </td>

                        <td>
                          <span className="table-source">
                            {getSource(event)}
                          </span>
                        </td>

                        <td>
                          <span className="table-action">
                            {displayValue(event?.action)}
                          </span>
                        </td>

                        <td>
                          <span
                            className={`severity severity-${String(
                              event?.severity || "unknown",
                            ).toLowerCase()}`}
                          >
                            {displayValue(event?.severity)}
                          </span>
                        </td>

                        <td>
                          <span className="quality-value">
                            {quality !== null ? `${quality}%` : "—"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>

        <aside className="event-detail-panel">
          <div className="events-panel-heading detail-heading">
            <div>
              <span className="panel-index">B / 02</span>
              <span className="panel-kicker">FORENSIC INSPECTION</span>
              <h3>Selected Event</h3>
            </div>

            {selectedEvent && (
              <span className="detail-format">
                {String(getFormat(selectedEvent)).toUpperCase()}
              </span>
            )}
          </div>

          {!selectedEvent ? (
            <div className="event-detail-empty">
              <span>SELECT AN EVENT</span>
              <p>
                Choose an event from the archive to inspect its
                normalized representation and preserved evidence.
              </p>
            </div>
          ) : (
            <div className="event-detail-content">
              <div className="event-identity">
                <span>EVENT ID</span>
                <strong>
                  {displayValue(selectedEvent.event_id)}
                </strong>
              </div>

              <div className="detail-grid">
                <div>
                  <span>PARSER</span>
                  <strong>{getParser(selectedEvent)}</strong>
                </div>

                <div>
                  <span>FORMAT</span>
                  <strong>{getFormat(selectedEvent)}</strong>
                </div>

                <div>
                  <span>QUALITY</span>
                  <strong>
                    {getQuality(selectedEvent) !== null
                      ? `${getQuality(selectedEvent)}%`
                      : "—"}
                  </strong>
                </div>

                <div>
                  <span>INTEGRITY</span>
                  <strong className="integrity-value">
                    {getIntegrity(selectedEvent)}
                  </strong>
                </div>
              </div>

              <div className="network-route">
                <div className="route-node">
                  <span>SOURCE</span>
                  <strong>{getSource(selectedEvent)}</strong>
                </div>

                <div className="route-line">
                  <span>EVENT FLOW</span>
                  <i />
                </div>

                <div className="route-node destination-node">
                  <span>DESTINATION</span>
                  <strong>
                    {getDestination(selectedEvent)}
                  </strong>
                </div>
              </div>

              <div className="detail-fields">
                <div>
                  <span>EVENT TYPE</span>
                  <strong>
                    {displayValue(selectedEvent.event_type)}
                  </strong>
                </div>

                <div>
                  <span>PROTOCOL</span>
                  <strong>
                    {displayValue(selectedEvent.protocol)}
                  </strong>
                </div>

                <div>
                  <span>ACTION</span>
                  <strong>
                    {displayValue(selectedEvent.action)}
                  </strong>
                </div>

                <div>
                  <span>SEVERITY</span>
                  <strong>
                    {displayValue(selectedEvent.severity)}
                  </strong>
                </div>
              </div>

              <div className="integrity-block">
                <div className="block-heading">
                  <span>INTEGRITY CHAIN</span>
                  <strong>
                    {getIntegrity(selectedEvent)}
                  </strong>
                </div>

                <div className="hash-row">
                  <span>SHA-256</span>
                  <code>
                    {displayValue(
                      selectedEvent.raw_hash ||
                        selectedEvent.integrity_hash,
                    )}
                  </code>
                </div>

                <div className="hash-row">
                  <span>PREVIOUS HASH</span>
                  <code>
                    {displayValue(selectedEvent.previous_hash)}
                  </code>
                </div>

                <div className="hash-row">
                  <span>CHAIN HASH</span>
                  <code>
                    {displayValue(selectedEvent.chain_hash)}
                  </code>
                </div>
              </div>

              <div className="raw-evidence">
                <div className="block-heading">
                  <span>ORIGINAL RAW EVENT</span>
                  <strong>PRESERVED</strong>
                </div>

                <pre>
                  {displayValue(selectedEvent.raw_event)}
                </pre>
              </div>

              <div className="event-metadata">
                <span>
                  CREATED {displayValue(selectedEvent.created_at)}
                </span>

                <span>
                  PARSE STATUS{" "}
                  {displayValue(selectedEvent.parse_status)}
                </span>

                <span>
                  SOURCE TYPE{" "}
                  {displayValue(selectedEvent.source_type)}
                </span>
              </div>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}

export default Events;