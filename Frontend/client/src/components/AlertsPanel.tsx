type SecurityAlert = {
  rule_id: string;
  rule_name: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  src_ip?: string;
  dest_ip?: string;
  dest_port?: number | string;
};

type AlertsPanelProps = {
  alerts: SecurityAlert[];
};

export default function AlertsPanel({
  alerts,
}: AlertsPanelProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Security Alerts
        </h2>

        <span className="text-sm text-muted-foreground">
          {alerts.length} alerts
        </span>
      </div>

      {alerts.length === 0 ? (
        <div className="rounded-lg border p-4 text-sm text-muted-foreground">
          No security alerts detected.
        </div>
      ) : (
        alerts.map((alert, index) => (
          <div
            key={`${alert.rule_id}-${index}`}
            className="rounded-lg border p-4"
          >
            <div className="flex items-center justify-between">
              <div>
                <div className="font-semibold">
                  {alert.rule_name}
                </div>

                <div className="text-xs text-muted-foreground">
                  {alert.rule_id}
                </div>
              </div>

              <span className="rounded px-2 py-1 text-xs font-semibold">
                {alert.severity}
              </span>
            </div>

            <p className="mt-2 text-sm">
              {alert.description}
            </p>

            <div className="mt-2 text-xs text-muted-foreground">
              Source: {alert.src_ip || "Unknown"}
              {" → "}
              {alert.dest_ip || "Unknown"}
              {alert.dest_port
                ? `:${alert.dest_port}`
                : ""}
            </div>
          </div>
        ))
      )}
    </div>
  );
}