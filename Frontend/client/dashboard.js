const eventRows = new Map();
const alertRows = new Map();
const state = { eventCount: 0, alertCount: 0, lastEventAt: null };
const $ = (id) => document.getElementById(id);

function safeText(value, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function displayTime(value) {
  if (value === null || value === undefined || value === "") return "-";
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? safeText(value) : date.toLocaleTimeString();
}

function setHealth(id, label, healthy) {
  $(`${id}-dot`).className = `dot ${healthy ? "ok" : "bad"}`;
  $(`${id}-status`).textContent = `${label} ${healthy ? "online" : "offline"}`;
}

function renderEventRow(message) {
  const event = message.event || {};
  const key = String(message.row_id || message.event_id || event.uid || `${event.ts}-${event.src_ip}-${event.dest_ip}-${event.src_port}`);
  if (eventRows.has(key)) return;
  const alerts = Array.isArray(message.alerts) ? message.alerts : [];
  const time = displayTime(event.ts);
  const destination = `${safeText(event.dest_ip)}:${safeText(event.dest_port)}`;
  const bytes = Number(event.orig_bytes || 0) + Number(event.resp_bytes || 0);
  const row = document.createElement("tr");
  row.dataset.search = `${event.src_ip || ""} ${destination} ${event.service || ""} ${event.proto || ""} ${alerts.map((alert) => alert.rule_name).join(" ")}`.toLowerCase();
  const values = [
    [time, ""],
    [safeText(event.src_ip), "source"],
    [destination, "destination"],
    [safeText(event.proto, "?").toUpperCase(), ""],
    [safeText(event.conn_state), "state"],
    [Number.isFinite(bytes) ? bytes.toLocaleString() : "-", ""],
    [alerts.length ? alerts.map((alert) => alert.rule_id).join(", ") : "—", alerts.length ? "event-alert" : ""],
  ];
  for (const [text, className] of values) {
    const cell = document.createElement("td");
    cell.textContent = text;
    if (className) cell.className = className;
    row.append(cell);
  }
  eventRows.set(key, row);
  if (eventRows.size > 250) eventRows.delete(eventRows.keys().next().value);
  $("events-body").prepend(row);
  $("events-body").querySelector(".empty")?.remove();
  state.eventCount += 1;
  state.lastEventAt = event.ts;
  updateMetrics();
}

function renderAlert(alert) {
  const key = String(alert.id || `${alert.rule_id}-${alert.timestamp}-${alert.src_ip}`);
  if (alertRows.has(key)) return;
  const card = document.createElement("article");
  card.className = "alert";
  const header = document.createElement("div");
  header.className = "alert-top";
  const severity = document.createElement("span");
  severity.className = `severity ${String(alert.severity || "low").toLowerCase()}`;
  severity.textContent = safeText(alert.severity, "LOW");
  const ruleId = document.createElement("span");
  ruleId.className = "rule-id";
  ruleId.textContent = safeText(alert.rule_id);
  header.append(severity, ruleId);
  const title = document.createElement("h3");
  title.textContent = safeText(alert.rule_name, "Security detection");
  const description = document.createElement("p");
  description.textContent = safeText(alert.description);
  const time = document.createElement("p");
  time.className = "alert-time";
  time.textContent = `${safeText(alert.src_ip, "Unknown source")} → ${safeText(alert.dest_ip, "Unknown destination")} · ${displayTime(alert.timestamp)}`;
  card.append(header, title, description, time);
  alertRows.set(key, card);
  if (alertRows.size > 100) alertRows.delete(alertRows.keys().next().value);
  $("alerts-list").prepend(card);
  $("alerts-list").querySelector(".empty")?.remove();
  state.alertCount += 1;
  updateMetrics();
}

function updateMetrics(summary = {}) {
  $("events-minute").textContent = Number(summary.events_last_minute ?? state.eventCount).toLocaleString();
  $("event-rate").innerHTML = `${Number(summary.events_per_second || 0).toFixed(2)}<em>/s</em>`;
  $("alert-count").textContent = Number(summary.alert_count ?? state.alertCount).toLocaleString();
  $("alert-total").textContent = String(state.alertCount);
  $("event-total").textContent = `${eventRows.size} recent events`;
  if (state.lastEventAt) $("last-event").textContent = `Last event ${displayTime(state.lastEventAt)}`;
}

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    const health = await response.json();
    setHealth("api", "API", response.ok);
    setHealth("kafka", "Kafka", health.kafka_connected);
    setHealth("db", "DB", health.database_connected);
    $("footer-dot").className = `dot ${health.database_connected ? "ok" : "bad"}`;
    $("footer-db").textContent = health.database_connected ? "PostgreSQL connected" : "PostgreSQL unavailable";
  } catch {
    setHealth("api", "API", false);
    setHealth("kafka", "Kafka", false);
    setHealth("db", "DB", false);
    $("footer-dot").className = "dot bad";
    $("footer-db").textContent = "API unavailable";
  }
}

async function loadHistory() {
  try {
    const [eventsResponse, alertsResponse, summaryResponse] = await Promise.all([
      fetch("/api/events?limit=100"),
      fetch("/api/alerts?limit=100"),
      fetch("/api/summary"),
    ]);
    if (!eventsResponse.ok || !alertsResponse.ok) throw new Error("History unavailable");
    const [events, alerts, summary] = await Promise.all([
      eventsResponse.json(), alertsResponse.json(), summaryResponse.json(),
    ]);
    for (const row of [...(events.events || [])].reverse()) {
      renderEventRow({ row_id: row.id, event: row.payload, alerts: [] });
    }
    for (const row of [...(alerts.alerts || [])].reverse()) renderAlert(row);
    updateMetrics(summary);
    $("event-total").textContent = `${events.events?.length || 0} stored events`;
    if (!eventRows.size) $("events-body").innerHTML = '<tr><td colspan="7" class="empty">No stored events yet</td></tr>';
    if (!alertRows.size) $("alerts-list").innerHTML = '<p class="empty">No security alerts recorded</p>';
  } catch {
    $("events-body").innerHTML = '<tr><td colspan="7" class="empty">History unavailable. Check the database connection.</td></tr>';
    $("alerts-list").innerHTML = '<p class="empty">Alert history unavailable</p>';
  }
}

function connectStream() {
  const source = new EventSource("/api/logs/stream");
  source.onopen = () => {
    $("stream-state").classList.add("live");
    $("stream-state").innerHTML = '<i class="dot ok"></i> STREAM LIVE';
  };
  source.onmessage = (message) => {
    try {
      const data = JSON.parse(message.data);
      if (data.type !== "log") return;
      renderEventRow(data);
      for (const alert of data.alerts || []) renderAlert(alert);
    } catch (error) {
      console.error("Invalid event stream message", error);
    }
  };
  source.onerror = () => {
    $("stream-state").classList.remove("live");
    $("stream-state").innerHTML = '<i class="dot bad"></i> RECONNECTING';
  };
}

$("event-search").addEventListener("input", (event) => {
  const query = event.target.value.trim().toLowerCase();
  for (const row of eventRows.values()) row.hidden = !row.dataset.search.includes(query);
});
$("refresh").addEventListener("click", () => window.location.reload());

loadHistory();
loadHealth();
connectStream();
window.setInterval(loadHealth, 5000);
