const $ = (id) => document.getElementById(id);
const state = {
  view: "overview",
  events: new Map(),
  alerts: new Map(),
  summary: {},
};
const MAX_RECENT_RECORDS = 500;

const VIEW_COPY = {
  overview: ["Operations overview", "Network activity, detection trends, and system health"],
  events: ["Live event history", "Inspect and filter raw Zeek connection records"],
  alerts: ["Alert investigation", "Review behavior-based detections and their evidence"],
};

const RULE_NAMES = {
  BRUTE_FORCE_001: "Repeated connection failures",
  PORT_SCAN_001: "Port scan activity",
  EXFIL_001: "Large outbound transfer",
  DNS_BURST_001: "DNS activity burst",
  UNUSUAL_PORT_001: "Rare destination port",
  LONG_CONNECTION_001: "Long-lived connection",
  CONNECTION_FLOOD_001: "High source connection rate",
  PERIODIC_BEACON_001: "Regular repeated connections",
};

function safeText(value, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function finiteNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function formatTime(value) {
  const timestamp = finiteNumber(value);
  if (timestamp !== null) {
    const date = new Date(timestamp * 1000);
    return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
  }
  if (typeof value === "string" && value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }
  return "-";
}

function eventTime(event) {
  return finiteNumber(event?.ts) ?? 0;
}

function alertTime(alert) {
  const timestamp = finiteNumber(alert?.timestamp);
  if (timestamp !== null) return timestamp;
  const createdAt = Date.parse(alert?.created_at || "");
  return Number.isFinite(createdAt) ? createdAt / 1000 : 0;
}

function formatBytes(value) {
  const bytes = finiteNumber(value);
  if (bytes === null || bytes < 0) return "n/a";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(value) {
  const seconds = finiteNumber(value);
  if (seconds === null || seconds < 0) return "n/a";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  return `${(seconds / 3600).toFixed(1)} hr`;
}

function setView(view) {
  if (!VIEW_COPY[view]) return;
  state.view = view;
  for (const name of Object.keys(VIEW_COPY)) {
    $(`${name}-view`).hidden = name !== view;
  }
  for (const tab of document.querySelectorAll(".view-tab")) {
    const selected = tab.dataset.view === view;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  }
  $("page-title").textContent = VIEW_COPY[view][0];
  $("page-description").textContent = VIEW_COPY[view][1];
  history.replaceState(null, "", view === "overview" ? location.pathname : `#${view}`);
}

function eventKey(event, rowId) {
  return String(event.uid || rowId || `${event.ts}-${event.src_ip}-${event.src_port}-${event.dest_ip}-${event.dest_port}`);
}

function alertKey(alert) {
  return `${alert.rule_id || "unknown"}|${alert.timestamp ?? alert.created_at ?? ""}|${alert.src_ip || ""}|${alert.dest_ip || ""}`;
}

function addEvent(event, rowId) {
  const key = eventKey(event, rowId);
  const previous = state.events.get(key);
  state.events.set(key, previous
    ? { ...previous, ...event, alerts: event.alerts?.length ? event.alerts : previous.alerts }
    : event);
  trimOldest(state.events, eventTime);
  if (state.view === "events") renderEvents();
  if (state.view === "overview") renderOverview();
  $("event-tab-count").textContent = state.events.size.toLocaleString();
}

function addAlert(alert) {
  const key = alertKey(alert);
  state.alerts.set(key, alert);
  trimOldest(state.alerts, alertTime);
  if (state.view === "alerts") renderAlerts();
  if (state.view === "overview") renderOverview();
  $("alert-tab-count").textContent = state.alerts.size.toLocaleString();
}

function trimOldest(records, getTime) {
  while (records.size > MAX_RECENT_RECORDS) {
    let oldestKey;
    let oldestTime = Infinity;
    for (const [key, record] of records) {
      const timestamp = getTime(record);
      if (timestamp < oldestTime) {
        oldestKey = key;
        oldestTime = timestamp;
      }
    }
    if (oldestKey === undefined) break;
    records.delete(oldestKey);
  }
}

function currentEvents() {
  return [...state.events.values()].sort((a, b) => eventTime(b) - eventTime(a));
}

function currentAlerts() {
  return [...state.alerts.values()].sort((a, b) => alertTime(b) - alertTime(a));
}

function createCell(row, text, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  row.append(cell);
  return cell;
}

function renderEvents() {
  const body = $("events-body");
  const query = $("event-search").value.trim().toLowerCase();
  const events = currentEvents().filter((event) => {
    const searchable = [event.src_ip, event.dest_ip, event.src_port, event.dest_port, event.service, event.proto, event.conn_state, event.uid].join(" ").toLowerCase();
    return searchable.includes(query);
  });
  body.replaceChildren();

  if (!events.length) {
    const row = document.createElement("tr");
    createCell(row, state.events.size ? "No events match this filter" : "No stored events yet", "empty").colSpan = 9;
    body.append(row);
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const originBytes = formatBytes(event.orig_bytes);
    const responseBytes = formatBytes(event.resp_bytes);
    const endpoint = (ip, port) => `${safeText(ip)}:${safeText(port)}`;
    createCell(row, formatTime(event.ts));
    createCell(row, endpoint(event.src_ip, event.src_port), "source");
    createCell(row, endpoint(event.dest_ip, event.dest_port), "destination");
    createCell(row, `${safeText(event.service, "unknown")} / ${safeText(event.proto, "?").toUpperCase()}`);
    createCell(row, safeText(event.conn_state, "unknown"), "state");
    createCell(row, formatDuration(event.duration));
    createCell(row, `${originBytes} / ${responseBytes}`);
    createCell(row, event.alerts?.length ? event.alerts.map((alert) => alert.rule_id).join(", ") : "-", event.alerts?.length ? "event-alert" : "");
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "detail-button";
    button.textContent = "Inspect";
    button.setAttribute("aria-expanded", "false");
    actionCell.append(button);
    row.append(actionCell);

    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.hidden = true;
    const detailsCell = document.createElement("td");
    detailsCell.colSpan = 9;
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(event, null, 2);
    detailsCell.append(pre);
    detailsRow.append(detailsCell);
    button.addEventListener("click", () => {
      detailsRow.hidden = !detailsRow.hidden;
      button.setAttribute("aria-expanded", String(!detailsRow.hidden));
      button.textContent = detailsRow.hidden ? "Inspect" : "Close";
    });
    body.append(row, detailsRow);
  }

  $("event-total").textContent = `${events.length} shown / ${state.events.size} loaded`;
  $("event-tab-count").textContent = state.events.size.toLocaleString();
}

function createBreakdownRow(label, count, maximum, tone = "") {
  const row = document.createElement("div");
  row.className = "breakdown-row";
  const name = document.createElement("span");
  name.className = "breakdown-label";
  name.textContent = label;
  const track = document.createElement("span");
  track.className = "bar-track";
  const fill = document.createElement("span");
  fill.className = `bar-fill ${tone}`;
  fill.style.width = `${maximum ? Math.max(2, (count / maximum) * 100) : 0}%`;
  track.append(fill);
  const amount = document.createElement("strong");
  amount.className = "breakdown-count";
  amount.textContent = count.toLocaleString();
  row.append(name, track, amount);
  return row;
}

function renderRateChart() {
  const svg = $("rate-chart");
  svg.replaceChildren();
  const rates = (state.summary.event_rate_series || []).map(finiteNumber).map((value) => value ?? 0);
  const maxRate = Math.max(...rates, 0.1);
  const ns = "http://www.w3.org/2000/svg";
  for (const y of [8, 24, 40]) {
    const grid = document.createElementNS(ns, "line");
    grid.setAttribute("x1", "0");
    grid.setAttribute("x2", "100");
    grid.setAttribute("y1", String(y));
    grid.setAttribute("y2", String(y));
    grid.setAttribute("class", "chart-grid-line");
    svg.append(grid);
  }

  if (!rates.length) return;
  const points = rates.map((rate, index) => {
    const x = rates.length === 1 ? 50 : (index / (rates.length - 1)) * 100;
    const y = 43 - (rate / maxRate) * 36;
    return [x, y];
  });
  const line = document.createElementNS(ns, "polyline");
  line.setAttribute("points", points.map(([x, y]) => `${x},${y}`).join(" "));
  line.setAttribute("class", "chart-line");
  const area = document.createElementNS(ns, "polygon");
  area.setAttribute("points", `0,47 ${points.map(([x, y]) => `${x},${y}`).join(" ")} 100,47`);
  area.setAttribute("class", "chart-area");
  svg.append(area, line);
  const last = points[points.length - 1];
  const point = document.createElementNS(ns, "circle");
  point.setAttribute("cx", String(last[0]));
  point.setAttribute("cy", String(last[1]));
  point.setAttribute("r", "1.4");
  point.setAttribute("class", "chart-point");
  svg.append(point);
}

function renderBreakdowns() {
  const alerts = currentAlerts();
  const severities = ["critical", "high", "medium", "low"];
  const severityCounts = Object.fromEntries(severities.map((severity) => [severity, 0]));
  const ruleCounts = {};
  const sourceCounts = {};
  const eventList = currentEvents();
  for (const alert of alerts) {
    const severity = String(alert.severity || "low").toLowerCase();
    if (severity in severityCounts) severityCounts[severity] += 1;
    ruleCounts[alert.rule_id || "UNKNOWN"] = (ruleCounts[alert.rule_id || "UNKNOWN"] || 0) + 1;
  }
  for (const event of eventList) {
    if (event.src_ip) sourceCounts[event.src_ip] = (sourceCounts[event.src_ip] || 0) + 1;
  }

  const severityTotal = Object.values(severityCounts).reduce((sum, count) => sum + count, 0);
  $("severity-total").textContent = severityTotal.toLocaleString();
  const severityContainer = $("severity-breakdown");
  severityContainer.replaceChildren(...severities.map((severity) => createBreakdownRow(severity.toUpperCase(), severityCounts[severity], Math.max(...Object.values(severityCounts), 1), severity)));

  const sources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const sourceContainer = $("top-sources");
  sourceContainer.replaceChildren();
  if (!sources.length) sourceContainer.append(emptyMessage("No source events loaded yet"));
  else {
    const maximum = Math.max(...sources.map(([, count]) => count), 1);
    for (const [source, count] of sources) sourceContainer.append(createBreakdownRow(source, count, maximum));
  }

  const rules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const ruleContainer = $("rule-breakdown");
  ruleContainer.replaceChildren();
  if (!rules.length) ruleContainer.append(emptyMessage("No rules have generated alerts in this history"));
  else {
    const maximum = Math.max(...rules.map(([, count]) => count), 1);
    for (const [ruleId, count] of rules) ruleContainer.append(createBreakdownRow(RULE_NAMES[ruleId] || ruleId, count, maximum));
  }
}

function emptyMessage(text) {
  const message = document.createElement("p");
  message.className = "empty";
  message.textContent = text;
  return message;
}

function renderCompactAlerts() {
  const container = $("recent-alerts");
  container.replaceChildren();
  const alerts = currentAlerts().slice(0, 5);
  if (!alerts.length) {
    container.append(emptyMessage("No alerts in the loaded history"));
    return;
  }
  for (const alert of alerts) {
    const row = document.createElement("article");
    row.className = "compact-alert";
    const severity = document.createElement("span");
    severity.className = `compact-severity ${String(alert.severity || "low").toLowerCase()}`;
    const copy = document.createElement("span");
    copy.className = "compact-copy";
    const title = document.createElement("strong");
    title.textContent = safeText(alert.rule_name, alert.rule_id);
    const context = document.createElement("small");
    context.textContent = `${safeText(alert.src_ip)} → ${safeText(alert.dest_ip)}`;
    copy.append(title, context);
    const time = document.createElement("time");
    time.className = "compact-time";
    time.textContent = Number.isFinite(alertTime(alert)) ? new Date(alertTime(alert) * 1000).toLocaleTimeString() : "-";
    row.append(severity, copy, time);
    container.append(row);
  }
}

function renderOverview() {
  const events = currentEvents();
  const rate = finiteNumber(state.summary.events_per_second) ?? 0;
  const count = finiteNumber(state.summary.events_last_minute) ?? 0;
  const sourceCount = new Set(events.map((event) => event.src_ip).filter(Boolean)).size;
  $("events-minute").textContent = count.toLocaleString();
  $("event-rate").innerHTML = `${rate.toFixed(2)}<em>/s</em>`;
  $("alert-count").textContent = state.alerts.size.toLocaleString();
  $("source-count").textContent = sourceCount.toLocaleString();
  $("chart-current-rate").textContent = `${rate.toFixed(2)} / sec`;
  $("chart-window-count").textContent = `${count.toLocaleString()} events in window`;
  $("event-tab-count").textContent = state.events.size.toLocaleString();
  $("alert-tab-count").textContent = state.alerts.size.toLocaleString();
  renderRateChart();
  renderBreakdowns();
  renderCompactAlerts();
}

function renderAlerts() {
  const container = $("alerts-list");
  const query = $("alert-search").value.trim().toLowerCase();
  const severity = $("severity-filter").value;
  const alerts = currentAlerts().filter((alert) => {
    const searchable = [alert.rule_id, alert.rule_name, alert.description, alert.src_ip, alert.dest_ip, alert.mitre_technique].join(" ").toLowerCase();
    return searchable.includes(query) && (severity === "all" || String(alert.severity || "").toLowerCase() === severity);
  });
  container.replaceChildren();

  if (!alerts.length) {
    container.append(emptyMessage(state.alerts.size ? "No alerts match these filters" : "No stored alerts yet"));
  }
  for (const alert of alerts) {
    const card = document.createElement("article");
    card.className = "alert-card";
    const head = document.createElement("div");
    head.className = "alert-card-head";
    const severityLabel = document.createElement("span");
    const severity = String(alert.severity || "LOW").toLowerCase();
    severityLabel.className = `severity ${severity}`;
    severityLabel.textContent = severity.toUpperCase();
    const ruleId = document.createElement("span");
    ruleId.className = "rule-id";
    ruleId.textContent = safeText(alert.rule_id);
    head.append(severityLabel, ruleId);
    const title = document.createElement("h3");
    title.textContent = safeText(alert.rule_name, "Network behavior alert");
    const description = document.createElement("p");
    description.textContent = safeText(alert.description);
    const context = document.createElement("div");
    context.className = "alert-context";
    for (const value of [
      `Source ${safeText(alert.src_ip)}`,
      `Destination ${safeText(alert.dest_ip)}`,
      `Port ${safeText(alert.dest_port)}`,
      `State ${safeText(alert.conn_state)}`,
      `Event ${formatTime(alert.timestamp ?? alert.created_at)}`,
      alert.event_id ? `Event #${alert.event_id}` : "",
    ].filter(Boolean)) {
      const item = document.createElement("span");
      item.textContent = value;
      context.append(item);
    }
    card.append(head, title, description, context);
    if (alert.evidence) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "Evidence and detection context";
      const evidence = document.createElement("pre");
      evidence.textContent = JSON.stringify({
        evidence: alert.evidence,
        technique: alert.mitre_technique,
        tactic: alert.mitre_tactic,
        service: alert.service,
        protocol: alert.proto,
        source_release: alert.source_release,
      }, null, 2);
      details.append(summary, evidence);
      card.append(details);
    }
    container.append(card);
  }
  $("alert-total").textContent = `${alerts.length} shown / ${state.alerts.size} loaded`;
  $("alert-tab-count").textContent = state.alerts.size.toLocaleString();
}

function renderLastEvent() {
  const latest = currentEvents()[0];
  $("last-event").textContent = latest ? `Latest event ${formatTime(latest.ts)}` : "No events received yet";
}

function setHealth(id, label, healthy) {
  $(`${id}-dot`).className = `dot ${healthy ? "ok" : "bad"}`;
  $(`${id}-status`).textContent = `${label} ${healthy ? "online" : "offline"}`;
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
      fetch("/api/events?limit=500"),
      fetch("/api/alerts?limit=500"),
      fetch("/api/summary"),
    ]);
    if (!eventsResponse.ok || !alertsResponse.ok || !summaryResponse.ok) throw new Error("History unavailable");
    const [events, alerts, summary] = await Promise.all([
      eventsResponse.json(), alertsResponse.json(), summaryResponse.json(),
    ]);
    state.events.clear();
    state.alerts.clear();
    const alertsByEvent = new Map();
    for (const alert of alerts.alerts || []) {
      state.alerts.set(alertKey(alert), alert);
      if (alert.event_id) {
        const related = alertsByEvent.get(alert.event_id) || [];
        related.push(alert);
        alertsByEvent.set(alert.event_id, related);
      }
    }
    for (const row of events.events || []) {
      const event = {
        ...row.payload,
        event_id: row.id,
        alerts: alertsByEvent.get(row.id) || [],
      };
      state.events.set(eventKey(event, row.id), event);
    }
    trimOldest(state.events, eventTime);
    trimOldest(state.alerts, alertTime);
    state.summary = summary;
    renderEvents();
    renderAlerts();
    renderOverview();
    renderLastEvent();
  } catch (error) {
    $("events-body").replaceChildren();
    const row = document.createElement("tr");
    createCell(row, "Could not load event history. Check API and database status.", "empty").colSpan = 9;
    $("events-body").append(row);
    $("alerts-list").replaceChildren(emptyMessage("Could not load alert history"));
  }
}

async function refreshSummary() {
  try {
    const response = await fetch("/api/summary");
    if (!response.ok) return;
    state.summary = await response.json();
    renderOverview();
  } catch {
    return;
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
      const event = data.event || {};
      event.alerts = data.alerts || [];
      addEvent(event);
      for (const alert of event.alerts) addAlert(alert);
      renderLastEvent();
    } catch (error) {
      console.error("Invalid event stream message", error);
    }
  };
  source.onerror = () => {
    $("stream-state").classList.remove("live");
    $("stream-state").innerHTML = '<i class="dot bad"></i> RECONNECTING';
  };
}

for (const tab of document.querySelectorAll(".view-tab")) {
  tab.addEventListener("click", () => setView(tab.dataset.view));
}
for (const button of document.querySelectorAll("[data-open-view]")) {
  button.addEventListener("click", () => setView(button.dataset.openView));
}
$("event-search").addEventListener("input", renderEvents);
$("alert-search").addEventListener("input", renderAlerts);
$("severity-filter").addEventListener("change", renderAlerts);
$("refresh-events").addEventListener("click", loadHistory);
window.addEventListener("hashchange", () => setView(location.hash.slice(1) || "overview"));

setView(location.hash.slice(1) || "overview");
loadHistory();
loadHealth();
connectStream();
window.setInterval(loadHealth, 5000);
window.setInterval(refreshSummary, 5000);