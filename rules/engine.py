from rules.detections import (
    rule_port_scan,
    rule_repeated_connection_failures,
    rule_large_outbound_transfer,
    rule_dns_burst,
)


# ============================================================
# REGISTERED DETECTION RULES
# ============================================================

RULES = [
    rule_port_scan,
    rule_repeated_connection_failures,
    rule_large_outbound_transfer,
    rule_dns_burst,
]


# ============================================================
# EVENT EVALUATION
# ============================================================

def evaluate_event(event):
    """
    Run every detection rule against a single Zeek event.

    Each rule independently decides whether the event contributes
    to a suspicious pattern.

    Returns:
        list: Zero or more generated alerts.
    """

    alerts = []

    for rule in RULES:

        try:
            result = rule(event)

            if not result:
                continue

            # ------------------------------------------------
            # Build the complete alert.
            # ------------------------------------------------

            alert = {
                **result,

                # Network information
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),

                # Event timing
                "timestamp": event.get("ts"),

                # Connection information
                "service": event.get("service"),
                "proto": event.get("proto"),
                "conn_state": event.get("conn_state"),

                # Traffic volume
                "orig_bytes": event.get("orig_bytes"),
                "resp_bytes": event.get("resp_bytes"),

                # Security classification
                "tactic": event.get("tactic"),

                # Dataset/source information
                "source_release": event.get("source_release"),
            }

            alerts.append(alert)

        except Exception as error:

            print(
                f"Rule error in "
                f"{rule.__name__}: {error}"
            )

    return alerts