import { useCallback, useEffect, useState } from "react";
import AlertsPanel from "../components/AlertsPanel";
import {
  Activity,
  AlertOctagon,
  ArrowDownRight,
  ArrowUpRight,
  BookOpen,
  Bot,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Globe2,
  Gauge,
  Layers3,
  Map,
  Menu,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  TestTube2,
  X,
  Zap,
} from "lucide-react";

type SecurityEvent = {
  ts?: number | string;
  src_ip?: string;
  dest_ip?: string;
  src_port?: number | string;
  dest_port?: number | string;
  proto?: string;
  tactic?: string;
  service?: string;
  event_type?: string;

  [key: string]: unknown;
};

type SecurityAlert = {
  rule_id: string;
  rule_name: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;

  src_ip?: string;
  dest_ip?: string;
  src_port?: number | string;
  dest_port?: number | string;

  timestamp?: number | string;
  service?: string;
  proto?: string;
  tactic?: string;
};

type OverviewSummary = {
  kafka_connected: boolean;
  events_per_second: number;
  events_last_minute: number;
  alert_count: number;
  top_alert_sources: { src_ip: string; count: number }[];
  alerts_by_rule: Record<string, number>;
  event_rate_series: number[];
  recent_alerts: SecurityAlert[];
  last_event_at: string | null;
};

type StreamMessage = {
  type: "log";
  event: SecurityEvent;
  alerts: SecurityAlert[];
};

type ViewKey =
  | "overview"
  | "logs"
  | "alerts"
  | "map"
  | "prediction"
  | "lab"
  | "docs";

const navItems: {
  key: ViewKey;
  label: string;
  meta?: string;
  icon: typeof Activity;
}[] = [
  {
    key: "overview",
    label: "Overview",
    icon: Activity,
  },
  {
    key: "logs",
    label: "Live Logs",
    meta: "LIVE",
    icon: TerminalSquare,
  },
  {
    key: "alerts",
    label: "Alerts",
    meta: "LIVE",
    icon: ShieldAlert,
  },
  {
    key: "map",
    label: "Threat Map",
    icon: Map,
  },
  {
    key: "prediction",
    label: "Prediction",
    icon: Sparkles,
  },
  {
    key: "lab",
    label: "Injection Lab",
    icon: TestTube2,
  },
  {
    key: "docs",
    label: "Documentation",
    icon: BookOpen,
  },
];

function LogoMark() {
  return (
    <div className="logo-mark" aria-hidden="true">
      <span className="logo-ring ring-one" />
      <span className="logo-ring ring-two" />
      <span className="logo-core" />
    </div>
  );
}

function StatusDot({
  tone = "green",
}: {
  tone?: "green" | "amber" | "red" | "blue";
}) {
  return <span className={`status-dot ${tone}`} aria-hidden="true" />;
}

function MetricCard({
  label,
  value,
  trend,
  trendTone,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  trend: string;
  trendTone: "up" | "down";
  icon: typeof Activity;
  accent: string;
}) {
  return (
    <article
      className="metric-card"
      style={{ "--metric-accent": accent } as React.CSSProperties}
    >
      <div className="metric-topline">
        <span>{label}</span>
        <Icon size={16} strokeWidth={1.6} />
      </div>

      <div className="metric-value">{value}</div>

      <div className={`metric-trend ${trendTone}`}>
        {trendTone === "up" ? (
          <ArrowUpRight size={13} />
        ) : (
          <ArrowDownRight size={13} />
        )}
        {trend}
      </div>

      <div className="metric-sparkline">
        <span />
        <span />
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
    </article>
  );
}

function EventChart({ rates }: { rates: number[] }) {
  const maxRate = Math.max(...rates, 1);
  const points = rates.map((rate, index) => ({
    x: index * (97 / Math.max(rates.length - 1, 1)) + 2,
    y: 96 - (rate / maxRate) * 82,
  }));
  const line = points.map(({ x, y }) => `${x},${y}`).join(" ");
  const area = points.length ? `2,100 ${line} 99,100` : "";

  return (
    <div
      className="event-chart"
      aria-label="Event velocity line chart"
    >
      <div className="chart-y-axis">
        <span>{maxRate.toFixed(1)}/s</span>
        <span>{(maxRate * 0.66).toFixed(1)}/s</span>
        <span>{(maxRate * 0.33).toFixed(1)}/s</span>
        <span>0/s</span>
      </div>

      <svg
        viewBox="0 0 103 100"
        preserveAspectRatio="none"
        role="img"
      >
        <defs>
          <linearGradient
            id="eventFill"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop
              offset="0%"
              stopColor="#72e8c0"
              stopOpacity=".33"
            />
            <stop
              offset="100%"
              stopColor="#72e8c0"
              stopOpacity=".02"
            />
          </linearGradient>
        </defs>

        {[25, 50, 75].map((y) => (
          <line
            key={y}
            x1="2"
            x2="99"
            y1={y}
            y2={y}
            className="chart-grid"
          />
        ))}

        {points.length > 0 && <polygon points={area} fill="url(#eventFill)" />}
        {points.length > 0 && <polyline points={line} fill="none" className="chart-line" />}
        {points.length > 0 && (
          <circle
            cx={points[points.length - 1].x}
            cy={points[points.length - 1].y}
            r="1.7"
            className="chart-last"
          />
        )}
      </svg>

      <div className="chart-x-axis">
        <span>60s ago</span>
        <span>40s ago</span>
        <span>20s ago</span>
        <span>Now</span>
      </div>
    </div>
  );
}

function SectionHeading({
  eyebrow,
  title,
  action,
  onAction,
}: {
  eyebrow: string;
  title: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="section-heading">
      <div>
        <span className="eyebrow">
          <span className="eyebrow-dot" />
          {eyebrow}
        </span>

        <h2>{title}</h2>
      </div>

      {action && (
        <button
          className="text-button"
          onClick={onAction}
        >
          {action}
          <ChevronRight size={14} />
        </button>
      )}
    </div>
  );
}

function Overview({
  onNotice,
  summary,
}: {
  onNotice: (message: string) => void;
  summary: OverviewSummary | null;
}) {
  const sourceColors = ["coral", "amber", "gold", "mint"];
  const maxSourceCount = Math.max(
    ...(summary?.top_alert_sources.map((source) => source.count) ?? []),
    1
  );

  return (
    <>
      <div className="breadcrumb">
        <span>WORKSPACE</span>
        <ChevronRight size={12} />
        <b>Overview</b>
      </div>

      <header className="page-header">
        <div>
          <h1>Operations overview</h1>
          <p>
            Your streaming security posture, at a glance.
          </p>
        </div>

        <div className="header-actions">
          <span className="live-pill">
            <StatusDot tone={summary?.kafka_connected ? "green" : "red"} />
            {summary?.kafka_connected ? "Kafka connected" : "Kafka disconnected"}{" "}
            <strong>{(summary?.events_per_second ?? 0).toFixed(2)} events/s</strong>
          </span>

          <button
            className="icon-button"
            aria-label="Search"
            onClick={() =>
              onNotice(
                "Global search is ready for your next query."
              )
            }
          >
            <Search size={16} />
          </button>

          <button
            className="icon-button"
            aria-label="Settings"
            onClick={() =>
              onNotice(
                "Workspace settings are available in the full product."
              )
            }
          >
            <Settings2 size={16} />
          </button>
        </div>
      </header>

      <div className="metrics-grid">
        <MetricCard
          label="Events (last minute)"
          value={(summary?.events_last_minute ?? 0).toLocaleString()}
          trend="records consumed by API"
          trendTone="down"
          icon={Activity}
          accent="#72e8c0"
        />

        <MetricCard
          label="Alerts (API session)"
          value={String(summary?.alert_count ?? 0)}
          trend="rule matches recorded"
          trendTone="down"
          icon={AlertOctagon}
          accent="#ff7c74"
        />

        <MetricCard
          label="Matched rules"
          value={String(Object.keys(summary?.alerts_by_rule ?? {}).length)}
          trend="distinct rules with detections"
          trendTone="down"
          icon={Gauge}
          accent="#e3b96b"
        />

        <MetricCard
          label="Kafka status"
          value={summary?.kafka_connected ? "Online" : "Offline"}
          trend={summary?.kafka_connected ? "consumer connected" : "waiting for broker"}
          trendTone={summary?.kafka_connected ? "down" : "up"}
          icon={Zap}
          accent="#8b9fff"
        />
      </div>

      <div className="main-grid">
        <section className="panel telemetry-panel">
          <SectionHeading
            eyebrow="Live telemetry"
            title="Event velocity"
            action="Open stream"
            onAction={() => onNotice("Open Live Logs to inspect individual events.")}
          />

          <EventChart rates={summary?.event_rate_series ?? []} />

          <div className="chart-legend">
            <span>
              <i className="legend-line mint" />
              Incoming events
            </span>

            <span>
              <i className="legend-line coral" />
              Detection threshold
            </span>

            <strong>
              Current <b>{(summary?.events_per_second ?? 0).toFixed(2)}/s</b>
            </strong>
          </div>
        </section>

        <section className="panel incidents-panel">
          <SectionHeading
            eyebrow="Priority queue"
            title="Open incidents"
            action={String(summary?.alert_count ?? 0)}
            onAction={() =>
              onNotice("Open Alerts to inspect detections recorded by this API session.")
            }
          />

          <div className="incident-list">
            {(summary?.recent_alerts ?? []).map((incident, index) => (
              <button
                className="incident-row"
                key={`${incident.rule_id}-${incident.timestamp}-${index}`}
                onClick={() =>
                  onNotice(`${incident.rule_name}: ${incident.description}`)
                }
              >
                <span
                  className={`incident-bar ${incident.severity.toLowerCase()}`}
                />

                <span className="incident-copy">
                  <strong>{incident.rule_name}</strong>

                  <small>
                    {incident.src_ip ?? "Unknown source"} <i>·</i> {incident.rule_id}
                  </small>
                </span>

                <span
                  className={`risk-chip ${incident.severity.toLowerCase()}`}
                >
                  {incident.severity}
                </span>

                <ChevronRight size={15} />
              </button>
            ))}
            {(!summary || summary.recent_alerts.length === 0) && (
              <div className="incident-copy">
                <strong>{summary ? "No detections yet" : "Waiting for API"}</strong>
                <small>{summary ? "No rules have matched in this API session." : "Live overview data unavailable."}</small>
              </div>
            )}
          </div>

          <button
            className="view-all"
            onClick={() =>
              onNotice("Open Alerts in the sidebar to inspect current detections.")
            }
          >
            View all incidents
            <ChevronRight size={14} />
          </button>
        </section>

        <section className="panel sources-panel">
          <SectionHeading
            eyebrow="Top sources"
            title="Alert volume"
          />

          <div className="source-list">
            {(summary?.top_alert_sources ?? []).map((source, index) => (
              <div
                className="source-row"
                key={source.src_ip}
              >
                <span className="source-ip">
                  {source.src_ip}
                </span>

                <div className="source-track">
                  <span
                    className={sourceColors[index % sourceColors.length]}
                    style={{
                      width: `${(source.count / maxSourceCount) * 100}%`,
                    }}
                  />
                </div>

                <b>{source.count}</b>

                <span className="source-rank">
                  0{index + 1}
                </span>
              </div>
            ))}
            {(!summary || summary.top_alert_sources.length === 0) && (
              <div className="toolbar-muted">No alerting sources recorded.</div>
            )}
          </div>
        </section>

        <section className="panel topology-panel">
          <SectionHeading
            eyebrow="Stream topology"
            title="Kafka pipeline"
            action="Inspect"
            onAction={() =>
              onNotice(
                "Pipeline inspection opened — all services are nominal."
              )
            }
          />

          <div className="topology-flow">
            <TopologyNode
              icon={Globe2}
              label="Collectors"
              value="Not connected"
              tone="mint"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Layers3}
              label="Kafka topics"
              value={summary?.kafka_connected ? "Connected" : "Offline"}
              tone="blue"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Shield}
              label="Detection"
              value={`${Object.keys(summary?.alerts_by_rule ?? {}).length} matched`}
              tone="amber"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Server}
              label="Storage"
              value="In memory"
              tone="mint"
            />
          </div>
        </section>
      </div>
    </>
  );
}

function TopologyNode({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="topology-node">
      <div className={`node-icon ${tone}`}>
        <Icon size={15} />
      </div>

      <span>{label}</span>

      <b>{value}</b>
    </div>
  );
}

function LogsView({
  onNotice,
  onAlerts,
}: {
  onNotice: (message: string) => void;
  onAlerts: (alerts: SecurityAlert[]) => void;
}) {
  const [logs, setLogs] = useState<SecurityEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [kafkaConnected, setKafkaConnected] = useState(false);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    let active = true;

    const checkKafka = async () => {
      try {
        const response = await fetch("/api/health");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const health = await response.json();
        if (active) {
          setKafkaConnected(Boolean(health.kafka_connected));
        }
      } catch {
        if (active) {
          setKafkaConnected(false);
        }
      }
    };

    void checkKafka();
    const timer = window.setInterval(() => void checkKafka(), 3000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const eventSource = new EventSource(
      "/api/logs/stream"
    );

    eventSource.onopen = () => {
      console.log("Connected to SIEM stream");
      setConnected(true);
    };

    eventSource.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);

        /*
         * New backend format:
         *
         * {
         *   type: "log",
         *   event: {...},
         *   alerts: [...]
         * }
         *
         * The fallback also allows raw events in case
         * the backend is temporarily using the old format.
         */

        let log: SecurityEvent;
        let detectedAlerts: SecurityAlert[] = [];

        if (
          parsed &&
          parsed.type === "log" &&
          parsed.event
        ) {
          const message = parsed as StreamMessage;

          log = message.event;
          detectedAlerts = Array.isArray(message.alerts)
            ? message.alerts
            : [];
        } else {
          log = parsed as SecurityEvent;
        }

        if (!paused) {
          setLogs((previous) => {
            return [log, ...previous].slice(0, 100);
          });
        }

        if (detectedAlerts.length > 0) {
          onAlerts(detectedAlerts);
        }
      } catch (error) {
        console.error(
          "Failed to parse log:",
          error
        );
      }
    };

    eventSource.onerror = () => {
      console.error("SSE connection error");
      setConnected(false);
    };

    return () => {
      eventSource.close();
    };
  }, [paused, onAlerts]);

  const formatTimestamp = (
    timestamp?: number | string
  ) => {
    if (
      timestamp === undefined ||
      timestamp === null ||
      timestamp === ""
    ) {
      return "—";
    }

    const numeric = Number(timestamp);

    const date = Number.isFinite(numeric)
      ? new Date(numeric * 1000)
      : new Date(String(timestamp));

    if (Number.isNaN(date.getTime())) {
      return String(timestamp);
    }

    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    });
  };

  const getRisk = (log: SecurityEvent) => {
    const tactic = String(
      log.tactic || ""
    ).toLowerCase();

    if (
      tactic.includes("credential") ||
      tactic.includes("execution") ||
      tactic.includes("persistence") ||
      tactic.includes("privilege")
    ) {
      return "HIGH";
    }

    if (
      tactic.includes("discovery") ||
      tactic.includes("reconnaissance")
    ) {
      return "MEDIUM";
    }

    return "LOW";
  };

  return (
    <WorkspaceView
      eyebrow="Live telemetry"
      title="Live event stream"
      description="Inspect normalized security events as they arrive from the Cap Scan pipeline."
    >
      <div className="stream-toolbar">
        <span className="live-pill">
          <StatusDot
            tone={connected && kafkaConnected ? "green" : "red"}
          />

          {connected && kafkaConnected
            ? "Streaming now"
            : connected
              ? "API connected, Kafka unavailable"
              : "Disconnected"}
        </span>

        <span className="toolbar-muted">
          {logs.length} events loaded
        </span>

        <button
          className="secondary-button"
          onClick={() => {
            setPaused((value) => !value);

            onNotice(
              paused
                ? "Stream resumed."
                : "Stream paused."
            );
          }}
        >
          <Clock3 size={14} />

          {paused
            ? "Resume stream"
            : "Pause stream"}
        </button>
      </div>

      <div className="log-table">
        <div className="log-head">
          <span>Timestamp</span>
          <span>Source</span>
          <span>Origin</span>
          <span>Event</span>
          <span>Risk</span>
        </div>

        {logs.map((log, index) => {
          const risk = getRisk(log);

          return (
            <div
              className="log-row"
              key={`${log.ts}-${log.src_ip}-${index}`}
            >
              <span>
                {formatTimestamp(log.ts)}
              </span>

              <span className="log-source">
                {String(
                  log.proto || "NETWORK"
                )}
              </span>

              <span>
                {String(
                  log.src_ip || "Unknown"
                )}
              </span>

              <span>
                {String(
                  log.tactic ||
                    log.event_type ||
                    log.service ||
                    "Security event"
                )}
              </span>

              <span
                className={`log-risk ${risk.toLowerCase()}`}
              >
                {risk}
              </span>
            </div>
          );
        })}

        {logs.length === 0 && (
          <div className="log-row">
            <span>Waiting...</span>
            <span>—</span>
            <span>—</span>
            <span>
              Waiting for Kafka events
            </span>
            <span>—</span>
          </div>
        )}
      </div>
    </WorkspaceView>
  );
}

function AlertsView({
  onNotice,
  liveAlerts,
}: {
  onNotice: (message: string) => void;
  liveAlerts: SecurityAlert[];
}) {
  const [alerts, setAlerts] = useState<SecurityAlert[]>(
    []
  );

  const loadAlerts = async () => {
    try {
      const response = await fetch(
        "/api/alerts"
      );

      if (!response.ok) {
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const data = await response.json();

      if (Array.isArray(data.alerts)) {
        setAlerts(data.alerts);
      }
    } catch (error) {
      console.error(
        "Failed to load alerts:",
        error
      );
    }
  };

  /*
   * Load existing alerts when the Alerts page opens.
   */
  useEffect(() => {
    loadAlerts();

    const timer = window.setInterval(
      loadAlerts,
      2000
    );

    return () =>
      window.clearInterval(timer);
  }, []);

  /*
   * Add newly detected alerts immediately.
   */
  useEffect(() => {
    if (liveAlerts.length === 0) {
      return;
    }

    setAlerts((previous) => {
      const combined = [
        ...liveAlerts,
        ...previous,
      ];

      const unique = combined.filter(
        (alert, index, array) => {
          const key = `${alert.rule_id}-${alert.timestamp}-${alert.src_ip}-${alert.dest_ip}-${alert.dest_port}`;

          return (
            index ===
            array.findIndex(
              (item) =>
                `${item.rule_id}-${item.timestamp}-${item.src_ip}-${item.dest_ip}-${item.dest_port}` ===
                key
            )
          );
        }
      );

      return unique.slice(0, 500);
    });
  }, [liveAlerts]);

  const criticalCount = alerts.filter(
    (alert) =>
      alert.severity === "CRITICAL"
  ).length;

  const highCount = alerts.filter(
    (alert) =>
      alert.severity === "HIGH"
  ).length;

  return (
    <WorkspaceView
      eyebrow="Priority queue"
      title="Incident response"
      description="Triage active detections, assign owners, and move high-risk events toward resolution."
    >
      <div className="alert-summary">
        <div>
          <span>Open alerts</span>
          <b>{alerts.length}</b>
        </div>

        <div>
          <span>Critical</span>
          <b className="coral-text">
            {criticalCount}
          </b>
        </div>

        <div>
          <span>High</span>
          <b className="amber-text">
            {highCount}
          </b>
        </div>

        <button
          className="primary-button"
          onClick={() =>
            onNotice(
              "Detection rules are running through the Kafka stream."
            )
          }
        >
          Detection rules
          <ChevronRight size={14} />
        </button>
      </div>

      <div className="alert-cards">
        {alerts.length === 0 ? (
          <div className="alert-card">
            <div className="alert-severity low">
              <Shield size={15} />
              waiting
            </div>

            <strong>
              No security alerts detected yet
            </strong>

            <span>
              Alerts will appear here when the
              backend detection engine matches
              an incoming Kafka event.
            </span>
          </div>
        ) : (
          alerts.map((alert, index) => (
            <button
              className="alert-card"
              key={`${alert.rule_id}-${alert.timestamp}-${index}`}
              onClick={() =>
                onNotice(
                  `${alert.rule_name}: ${alert.description}`
                )
              }
            >
              <div
                className={`alert-severity ${alert.severity.toLowerCase()}`}
              >
                <AlertOctagon size={15} />
                {alert.severity}
              </div>

              <strong>
                {alert.rule_name}
              </strong>

              <span>
                {alert.src_ip ||
                  "Unknown source"}

                {alert.dest_ip && (
                  <>
                    {" "}
                    <i>→</i>{" "}
                    {alert.dest_ip}
                  </>
                )}

                {alert.dest_port && (
                  <>
                    {" "}
                    <i>·</i> port{" "}
                    {String(
                      alert.dest_port
                    )}
                  </>
                )}
              </span>

              <span>
                {alert.description}
              </span>

              <div className="alert-card-footer">
                <span>
                  {alert.rule_id}
                </span>

                <b>
                  {alert.service ||
                    alert.proto ||
                    "DETECTION"}
                </b>

                <ChevronRight size={15} />
              </div>
            </button>
          ))
        )}
      </div>
    </WorkspaceView>
  );
}

function WorkspaceView({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <div className="breadcrumb">
        <span>WORKSPACE</span>
        <ChevronRight size={12} />
        <b>{title}</b>
      </div>

      <header className="page-header">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" />
            {eyebrow}
          </span>

          <h1>{title}</h1>

          <p>{description}</p>
        </div>

        <div className="header-actions">
          <span className="live-pill">
            <StatusDot />
            Pipeline nominal
          </span>

          <button
            className="icon-button"
            aria-label="Search"
          >
            <Search size={16} />
          </button>
        </div>
      </header>

      {children}
    </>
  );
}

function SimpleView({
  view,
  onNotice,
}: {
  view: ViewKey;
  onNotice: (message: string) => void;
}) {
  const content: Record<
    string,
    {
      eyebrow: string;
      title: string;
      desc: string;
      icon: typeof Activity;
      tone: string;
    }
  > = {
    map: {
      eyebrow: "Global activity",
      title: "Threat map",
      desc: "A geographic view of active sources and detection clusters across your edge.",
      icon: Globe2,
      tone: "blue",
    },

    prediction: {
      eyebrow: "Risk intelligence",
      title: "Prediction",
      desc: "Model-assisted signals surface likely attack paths before they become incidents.",
      icon: Bot,
      tone: "purple",
    },

    lab: {
      eyebrow: "Safe simulation",
      title: "Injection lab",
      desc: "Test detection rules against controlled payloads without touching production streams.",
      icon: Code2,
      tone: "amber",
    },

    docs: {
      eyebrow: "Reference",
      title: "Documentation",
      desc: "Architecture notes, event schemas, and operating guidance for Cap Scan.",
      icon: BookOpen,
      tone: "mint",
    },
  };

  const item = content[view];
  const Icon = item.icon;

  return (
    <WorkspaceView
      eyebrow={item.eyebrow}
      title={item.title}
      description={item.desc}
    >
      <section className="empty-workspace">
        <div
          className={`empty-icon ${item.tone}`}
        >
          <Icon size={27} />
        </div>

        <span className="eyebrow">
          <span className="eyebrow-dot" />
          Prototype workspace
        </span>

        <h2>
          {item.title} is ready to extend
        </h2>

        <p>
          This view is wired into the local
          prototype so you can shape the next
          workflow without losing the visual
          system.
        </p>

        <button
          className="primary-button"
          onClick={() =>
            onNotice(
              `${item.title} workspace selected.`
            )
          }
        >
          Explore workspace
          <ChevronRight size={14} />
        </button>
      </section>
    </WorkspaceView>
  );
}

export default function Home() {
  const [view, setView] =
    useState<ViewKey>("overview");

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

  const [toast, setToast] =
    useState("");

  const [overviewSummary, setOverviewSummary] =
    useState<OverviewSummary | null>(null);

  /*
   * Stores alerts received from the live SSE stream.
   */
  const [liveAlerts, setLiveAlerts] =
    useState<SecurityAlert[]>([]);

  useEffect(() => {
    let active = true;

    const loadSummary = async () => {
      try {
        const response = await fetch("/api/summary");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const summary = (await response.json()) as OverviewSummary;
        if (active) {
          setOverviewSummary(summary);
        }
      } catch {
        if (active) {
          setOverviewSummary(null);
        }
      }
    };

    void loadSummary();
    const timer = window.setInterval(() => void loadSummary(), 3000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!toast) {
      return;
    }

    const timer = window.setTimeout(
      () => setToast(""),
      3000
    );

    return () =>
      window.clearTimeout(timer);
  }, [toast]);

  const chooseView = (
    nextView: ViewKey
  ) => {
    setView(nextView);
    setSidebarOpen(false);
  };

  const handleNewAlerts = useCallback((
    newAlerts: SecurityAlert[]
  ) => {
    setLiveAlerts((previous) => [
      ...newAlerts,
      ...previous,
    ].slice(0, 100));
  }, []);

  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${
          sidebarOpen ? "open" : ""
        }`}
      >
        <div className="brand">
          <LogoMark />

          <div>
            <strong>
              Cap<span> Scan</span>
            </strong>

            <small>
              SECURITY OBSERVABILITY
            </small>
          </div>

          <button
            className="sidebar-close"
            onClick={() =>
              setSidebarOpen(false)
            }
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        <div className="workspace-label">
          <span>WORKSPACE</span>
          <b>DEMO / LAB</b>
        </div>

        <nav
          className="nav-list"
          aria-label="Primary navigation"
        >
          {navItems.map(
            ({
              key,
              label,
              meta,
              icon: Icon,
            }) => (
              <button
                key={key}
                onClick={() =>
                  chooseView(key)
                }
                className={`nav-item ${
                  view === key
                    ? "active"
                    : ""
                }`}
              >
                <Icon
                  size={17}
                  strokeWidth={1.7}
                />

                <span>{label}</span>

                {meta && (
                  <em>{meta}</em>
                )}

                {view === key && (
                  <i className="active-line" />
                )}
              </button>
            )
          )}
        </nav>

        <div className="sidebar-spacer" />

        <div className="pipeline-card">
          <div className="pipeline-label">
            <StatusDot tone={overviewSummary?.kafka_connected ? "green" : "red"} />
            PIPELINE HEALTH
          </div>

          <strong>
            {overviewSummary?.kafka_connected ? "Connected" : "Offline"}{" "}
            <small>{overviewSummary ? "Kafka consumer" : "API unavailable"}</small>
          </strong>

          <p>
            {overviewSummary?.kafka_connected
              ? `${overviewSummary.events_last_minute.toLocaleString()} events in the last minute`
              : "Waiting for the API and Kafka broker"}
          </p>
        </div>

        <button
          className="doc-link"
          onClick={() =>
            chooseView("docs")
          }
        >
          <BookOpen size={15} />
          Documentation
          <ChevronRight size={14} />
        </button>

        <div className="profile">
          <div className="avatar">
            AR
          </div>

          <div>
            <strong>
              Alex Rivera
            </strong>

            <span>
              Security analyst
            </span>
          </div>

          <ChevronRight size={15} />
        </div>
      </aside>

      {sidebarOpen && (
        <button
          className="sidebar-backdrop"
          onClick={() =>
            setSidebarOpen(false)
          }
          aria-label="Close navigation"
        />
      )}

      <main className="main-content">
        <div className="mobile-topbar">
          <button
            className="icon-button"
            onClick={() =>
              setSidebarOpen(true)
            }
            aria-label="Open navigation"
          >
            <Menu size={19} />
          </button>

          <div className="mobile-brand">
            <LogoMark />

            <strong>
              Sentinel<span>Stream</span>
            </strong>
          </div>

          <button
            className="icon-button"
            onClick={() =>
              setToast(
                "Global search is ready for your next query."
              )
            }
            aria-label="Search"
          >
            <Search size={16} />
          </button>
        </div>

        {view === "overview" && (
          <Overview
            onNotice={setToast}
            summary={overviewSummary}
          />
        )}

        {view === "logs" && (
          <LogsView
            onNotice={setToast}
            onAlerts={handleNewAlerts}
          />
        )}

        {view === "alerts" && (
          <AlertsView
            onNotice={setToast}
            liveAlerts={liveAlerts}
          />
        )}

        {(
          view === "map" ||
          view === "prediction" ||
          view === "lab" ||
          view === "docs"
        ) && (
          <SimpleView
            view={view}
            onNotice={setToast}
          />
        )}

        <footer className="app-footer">
          <span>
            <StatusDot tone={overviewSummary?.kafka_connected ? "green" : "red"} />
            {overviewSummary?.kafka_connected ? "Kafka connected" : "Backend unavailable"}
          </span>

          <span>
            {overviewSummary?.last_event_at
              ? `Last event ${new Date(overviewSummary.last_event_at).toLocaleTimeString()}`
              : "No events received this API session"}
          </span>

          <span>
            Cap Scan
            v0.9.4-demo
          </span>
        </footer>
      </main>

      {toast && (
        <div
          className="toast"
          role="status"
        >
          <CircleDot size={15} />

          {toast}

          <button
            onClick={() =>
              setToast("")
            }
            aria-label="Dismiss notification"
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
}