// =========================================================
// ZELTA ULPF — Frontend Logic
// =========================================================

const API_BASE = "http://127.0.0.1:8000/api/v1";


// =========================================================
// SAMPLE LOGS
// =========================================================

const examples = {

    syslog:
        '<134>Aug 20 14:32:10 firewall src=10.10.10.5 dst=10.10.10.20 dport=22 action=deny',

    json:
        '{"timestamp":"2026-08-20T14:32:10","sourceAddress":"10.10.10.5","destinationAddress":"10.10.10.20","destinationPort":22,"action":"blocked"}',

    cef:
        'CEF:0|VendorX|Firewall|1.0|1001|Connection Blocked|8|src=10.10.10.5 dst=10.10.10.20 dpt=22 act=blocked',

    xml:
        '<security_event><timestamp>2026-08-20T14:32:10</timestamp><source_ip>10.10.10.5</source_ip><destination_ip>10.10.10.20</destination_ip><destination_port>22</destination_port><action>blocked</action></security_event>',

    csv:
        'timestamp,src,dst,dport,action\n2026-08-20T14:32:10,10.10.10.5,10.10.10.20,22,blocked',

    leef:
        'LEEF:2.0|VendorX|Firewall|1.0|1001|src=10.10.10.5\tdst=10.10.10.20\tdport=22\tact=blocked',

    unknown:
        'FIREWALL_ALERT|device=FW01|user=admin|status=blocked|reason=malicious'

};


// =========================================================
// DOM ELEMENTS
// =========================================================

const logInput = document.getElementById("logInput");

const processBtn = document.getElementById("processBtn");
const clearBtn = document.getElementById("clearBtn");

const resultSection = document.getElementById("resultSection");

const errorMessage = document.getElementById("errorMessage");


// Statistics
const eventCount = document.getElementById("eventCount");
const formatCount = document.getElementById("formatCount");
const formatList = document.getElementById("formatList");

const pipelineStatus = document.getElementById("pipelineStatus");

const qualityScoreCard =
    document.getElementById("qualityScoreCard");

const qualityStatusCard =
    document.getElementById("qualityStatusCard");


// API status
const apiStatusDot =
    document.getElementById("apiStatusDot");

const apiStatus =
    document.getElementById("apiStatus");


// Processing result
const detectedFormat =
    document.getElementById("detectedFormat");

const parserName =
    document.getElementById("parserName");

const qualityStatus =
    document.getElementById("qualityStatus");

const qualityScore =
    document.getElementById("qualityScore");

const qualityConfidence =
    document.getElementById("qualityConfidence");

const qualityChecks =
    document.getElementById("qualityChecks");

const formatMessage =
    document.getElementById("formatMessage");

const formatSuggestion =
    document.getElementById("formatSuggestion");

const identifiedData =
    document.getElementById("identifiedData");

const integrityStatus =
    document.getElementById("integrityStatus");

const chainStatus =
    document.getElementById("chainStatus");

const eventId =
    document.getElementById("eventId");


// Normalized event
const timestamp =
    document.getElementById("timestamp");

const source =
    document.getElementById("source");

const sourceType =
    document.getElementById("sourceType");

const sourceIp =
    document.getElementById("sourceIp");

const destinationIp =
    document.getElementById("destinationIp");

const destinationPort =
    document.getElementById("destinationPort");

const protocol =
    document.getElementById("protocol");

const eventType =
    document.getElementById("eventType");

const action =
    document.getElementById("action");

const severity =
    document.getElementById("severity");


// Raw event
const rawEvent =
    document.getElementById("rawEvent");

const rawHash =
    document.getElementById("rawHash");

const chainHash =
    document.getElementById("chainHash");


// Universal JSON
const normalizedJson =
    document.getElementById("normalizedJson");


// =========================================================
// API STATUS
// =========================================================

async function checkApiStatus() {

    try {

        const response =
            await fetch(`${API_BASE}/health`);

        if (!response.ok) {
            throw new Error("API unavailable");
        }

        apiStatus.textContent = "API: Online";

        apiStatusDot.style.background =
            "#16a34a";

    } catch (error) {

        apiStatus.textContent =
            "API: Offline";

        apiStatusDot.style.background =
            "#dc2626";
    }
}


// =========================================================
// LOAD STATISTICS
// =========================================================

async function loadStats() {

    try {

        const statsResponse =
            await fetch(`${API_BASE}/stats`, {
                headers: {
                    "X-API-Key": "default_api_key_change_me"
                }
            });

        if (!statsResponse.ok) {
            throw new Error("Could not load statistics");
        }

        const stats =
            await statsResponse.json();


        eventCount.textContent =
            stats.total_events ?? 0;


        const formats =
            stats.supported_formats ?? [];


        formatCount.textContent =
            formats.length;


        formatList.textContent =
            formats.join(" • ");


    } catch (error) {

        eventCount.textContent = "—";
        formatCount.textContent = "—";
        formatList.textContent = "API unavailable";
    }
}


// =========================================================
// DISPLAY VALUE
// =========================================================

function displayValue(value) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "—";
    }

    return String(value);
}


// =========================================================
// SHOW ERROR
// =========================================================

function showError(message) {

    errorMessage.textContent = message;

    errorMessage.classList.remove("hidden");
}


function hideError() {

    errorMessage.textContent = "";

    errorMessage.classList.add("hidden");
}


// =========================================================
// DISPLAY RESULT
// =========================================================

function displayResult(data) {

    const event = data.event || {};

    const quality = data.quality || {};

    const integrity = data.integrity || {};

    const format = data.format || {};


    // -----------------------------------------------------
    // Result summary
    // -----------------------------------------------------

    detectedFormat.textContent =
        displayValue(format.status === "supported"
            ? format.format
            : "Unknown");


    parserName.textContent =
        displayValue(event.parser);


    qualityStatus.textContent =
        displayValue(quality.status);


    qualityScore.textContent =
        displayValue(quality.quality_score);

    qualityConfidence.textContent =
        displayValue(quality.confidence);

    const checks = quality.checks || {};
    qualityChecks.textContent =
        `C:${displayValue(checks.completeness)}% | V:${displayValue(checks.validity)}% | K:${displayValue(checks.consistency)}%`;

    formatMessage.textContent =
        displayValue(format.message || format.reason);

    const probableFormat =
        format.status === "supported"
            ? format.format
            : (format.suggested_format || "unknown");

    const formatLabels = {
        "vendor-key-value": "VENDOR-KV",
        "pipe-delimited": "PIPE",
        "csv-like": "CSV",
        "unknown": "UNKNOWN",
    };

    formatSuggestion.textContent =
        displayValue(formatLabels[probableFormat] || probableFormat.toUpperCase());

    const extracted = event.extracted_data || format.extracted_data || {};
    identifiedData.textContent =
        Object.keys(extracted).length
            ? Object.entries(extracted).map(([key, value]) => `${key}=${value}`).join(" | ")
            : "—";


    integrityStatus.textContent =
        integrity.verified
            ? "Verified"
            : "Failed";

    chainStatus.textContent =
        integrity.chain_verified
            ? "Verified"
            : "Failed";


    eventId.textContent =
        displayValue(event.event_id);


    // -----------------------------------------------------
    // Normalized fields
    // -----------------------------------------------------

    timestamp.textContent =
        displayValue(event.timestamp);


    source.textContent =
        displayValue(event.source);


    sourceType.textContent =
        displayValue(event.source_type);


    sourceIp.textContent =
        displayValue(event.source_ip);


    destinationIp.textContent =
        displayValue(event.destination_ip);


    destinationPort.textContent =
        displayValue(event.destination_port);


    protocol.textContent =
        displayValue(event.protocol);


    eventType.textContent =
        displayValue(event.event_type);


    action.textContent =
        displayValue(event.action);


    severity.textContent =
        displayValue(event.severity);


    // -----------------------------------------------------
    // Raw event
    // -----------------------------------------------------

    rawEvent.textContent =
        displayValue(event.raw_event);


    rawHash.textContent =
        displayValue(integrity.sha256);

    chainHash.textContent =
        displayValue(integrity.chain_hash);


    // -----------------------------------------------------
    // Universal JSON
    // -----------------------------------------------------

    normalizedJson.textContent =
        JSON.stringify(event, null, 4);


    // -----------------------------------------------------
    // Dashboard statistics
    // -----------------------------------------------------

    qualityScoreCard.textContent =
        displayValue(quality.quality_score);


    qualityStatusCard.textContent =
        displayValue(quality.status);

    // Make unknown-format detection visually obvious.
    if (format.status === "unknown") {
        detectedFormat.textContent = "UNKNOWN";
    }


    pipelineStatus.textContent =
        "Processed";


    // -----------------------------------------------------
    // Show results
    // -----------------------------------------------------

    resultSection.classList.remove("hidden");

}


// =========================================================
// PROCESS LOG
// =========================================================

async function processLog() {

    hideError();


    const log =
        logInput.value.trim();


    if (!log) {

        showError(
            "Please enter a log event before processing."
        );

        return;
    }


    processBtn.disabled = true;

    processBtn.textContent =
        "Processing...";

    pipelineStatus.textContent =
        "Processing";


    try {

        const response =
            await fetch(`${API_BASE}/events`, {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",
                    "X-API-Key": "default_api_key_change_me"
                },

                body: JSON.stringify({
                    log: log
                })
            });


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Log processing failed."
            );
        }


        displayResult(data);


        // Refresh total event count
        await loadStats();


    } catch (error) {

        pipelineStatus.textContent =
            "Error";


        showError(
            error.message ||
            "Could not connect to the ULPF API."
        );


    } finally {

        processBtn.disabled = false;

        processBtn.textContent =
            "Process Log";
    }
}


// =========================================================
// CLEAR
// =========================================================

function clearLog() {

    logInput.value = "";

    hideError();

    resultSection.classList.add("hidden");

    pipelineStatus.textContent =
        "Ready";

    qualityScoreCard.textContent =
        "—";

    qualityStatusCard.textContent =
        "No event processed";
}


// =========================================================
// EXAMPLE BUTTONS
// =========================================================

document
    .querySelectorAll(".example-btn")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                const type =
                    button.dataset.example;

                logInput.value =
                    examples[type] || "";

                hideError();

                logInput.focus();
            }
        );

    });


// =========================================================
// BUTTON EVENTS
// =========================================================

processBtn.addEventListener(
    "click",
    processLog
);


clearBtn.addEventListener(
    "click",
    clearLog
);


// =========================================================
// INITIALIZE DASHBOARD
// =========================================================

async function initializeDashboard() {

    await checkApiStatus();

    await loadStats();
}


initializeDashboard();