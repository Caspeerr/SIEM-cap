import { useEffect, useMemo, useState } from "react";
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

/*
 * These are kept for the overview UI.
 * The actual live alerts are shown in AlertsView.
 */
const incidents = [
  {
    title: "Brute-force authentication pattern",
    ip: "185.220.101.42",
    age: "2m ago",
    level: "critical",
    score: "92",
  },
  {
    title: "Port scan across public edge",
    ip: "45.141.84.19",
    age: "8m ago",
    level: "high",
    score: "81",
  },
  {
    title: "Impossible travel detected",
    ip: "103.82.118.7",
    age: "14m ago",
    level: "medium",
    score: "68",
  },
];

const sources = [
  {
    ip: "185.220.101.42",
    count: 86,
    color: "coral",
  },
  {
    ip: "45.141.84.19",
    count: 65,
    color: "amber",
  },
  {
    ip: "103.82.118.7",
    count: 49,
    color: "gold",
  },
  {
    ip: "91.240.118.11",
    count: 31,
    color: "mint",
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

function EventChart({ tick }: { tick: number }) {
  const points = useMemo(() => {
    const base = [
      22, 25, 34, 31, 40, 33, 46, 50, 36, 26, 41, 49, 47, 57, 51, 56, 54,
      64, 57, 67,
    ];

    return base.map(
      (value, index) => value + Math.sin((tick + index) / 5) * 2.5
    );
  }, [tick]);

  const line = points
    .map((value, index) => `${index * 5.1 + 2},${100 - value}`)
    .join(" ");

  const area = `2,100 ${line} 99,100`;

  return (
    <div
      className="event-chart"
      aria-label="Event velocity line chart"
    >
      <div className="chart-y-axis">
        <span>3k</span>
        <span>2k</span>
        <span>1k</span>
        <span>0</span>
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

        <polygon
          points={area}
          fill="url(#eventFill)"
        />

        <polyline
          points={line}
          fill="none"
          className="chart-line"
        />

        <circle
          cx={points.length * 5.1 - 3}
          cy={100 - points[points.length - 1]}
          r="1.7"
          className="chart-last"
        />
      </svg>

      <div className="chart-x-axis">
        <span>15:30</span>
        <span>15:35</span>
        <span>15:40</span>
        <span>15:42</span>
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
  tick,
}: {
  onNotice: (message: string) => void;
  tick: number;
}) {
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
            <StatusDot />
            Live stream{" "}
            <strong>
              {(2.418 + (tick % 6) / 100).toFixed(1)}k events/s
            </strong>
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
          label="Events / sec"
          value={tick % 7 === 0 ? "2,431" : "2,418"}
          trend="+12.6% vs. yesterday"
          trendTone="up"
          icon={Activity}
          accent="#72e8c0"
        />

        <MetricCard
          label="Open incidents"
          value="12"
          trend="+3 today vs. yesterday"
          trendTone="up"
          icon={AlertOctagon}
          accent="#ff7c74"
        />

        <MetricCard
          label="Mean risk score"
          value="68.4"
          trend="+5.2 pts vs. yesterday"
          trendTone="up"
          icon={Gauge}
          accent="#e3b96b"
        />

        <MetricCard
          label="Kafka lag"
          value="34 ms"
          trend="-18.3% vs. yesterday"
          trendTone="down"
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
            onAction={() =>
              onNotice("Opening the live event stream…")
            }
          />

          <EventChart tick={tick} />

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
              Peak <b>2,842/s</b>
            </strong>
          </div>
        </section>

        <section className="panel incidents-panel">
          <SectionHeading
            eyebrow="Priority queue"
            title="Open incidents"
            action="12"
            onAction={() =>
              onNotice(
                "12 open incidents are currently prioritized by risk score."
              )
            }
          />

          <div className="incident-list">
            {incidents.map((incident) => (
              <button
                className="incident-row"
                key={incident.title}
                onClick={() =>
                  onNotice(
                    `${incident.title} · risk score ${incident.score}`
                  )
                }
              >
                <span
                  className={`incident-bar ${incident.level}`}
                />

                <span className="incident-copy">
                  <strong>{incident.title}</strong>

                  <small>
                    {incident.ip} <i>·</i> {incident.age}
                  </small>
                </span>

                <span
                  className={`risk-chip ${incident.level}`}
                >
                  {incident.score}
                </span>

                <ChevronRight size={15} />
              </button>
            ))}
          </div>

          <button
            className="view-all"
            onClick={() =>
              onNotice(
                "Incident queue expanded — use Alerts in the sidebar for triage."
              )
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
            {sources.map((source, index) => (
              <div
                className="source-row"
                key={source.ip}
              >
                <span className="source-ip">
                  {source.ip}
                </span>

                <div className="source-track">
                  <span
                    className={source.color}
                    style={{
                      width: `${(source.count / 90) * 100}%`,
                    }}
                  />
                </div>

                <b>{source.count}</b>

                <span className="source-rank">
                  0{index + 1}
                </span>
              </div>
            ))}
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
              value="8 online"
              tone="mint"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Layers3}
              label="Kafka topics"
              value="6 active"
              tone="blue"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Shield}
              label="Detection"
              value="99.1%"
              tone="amber"
            />

            <span className="flow-line" />

            <TopologyNode
              icon={Server}
              label="Storage"
              value="Healthy"
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
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const eventSource = new EventSource(
      "http://localhost:8000/api/logs/stream"
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
      description="Inspect normalized security events as they arrive from the SentinelStream pipeline."
    >
      <div className="stream-toolbar">
        <span className="live-pill">
          <StatusDot
            tone={connected ? "green" : "red"}
          />

          {connected
            ? "Streaming now"
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
        "http://localhost:8000/api/alerts"
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
      desc: "Architecture notes, event schemas, and operating guidance for SentinelStream.",
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

  const [tick, setTick] =
    useState(0);

  /*
   * Stores alerts received from the live SSE stream.
   */
  const [liveAlerts, setLiveAlerts] =
    useState<SecurityAlert[]>([]);

  useEffect(() => {
    const timer = window.setInterval(
      () =>
        setTick(
          (value) => value + 1
        ),
      4000
    );

    return () =>
      window.clearInterval(timer);
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

  const handleNewAlerts = (
    newAlerts: SecurityAlert[]
  ) => {
    setLiveAlerts((previous) => [
      ...newAlerts,
      ...previous,
    ].slice(0, 100));
  };

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
              Sentinel<span>Stream</span>
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
            <StatusDot />
            PIPELINE HEALTH
          </div>

          <strong>
            99.98%{" "}
            <small>nominal</small>
          </strong>

          <div className="pipeline-meter">
            <span />
          </div>

          <p>
            Kafka cluster · 1 broker online
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
            tick={tick}
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
            <StatusDot />
            All systems operational
          </span>

          <span>
            Last sync 15:42:
            {String(
              18 + (tick % 7)
            ).padStart(2, "0")}{" "}
            UTC
          </span>

          <span>
            SentinelStream
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