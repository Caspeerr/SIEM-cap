from rules.detections import (
    rule_port_scan,
    rule_repeated_connection_failures,
    rule_large_outbound_transfer,
    rule_dns_burst,
)


RULES = [
    rule_port_scan,
    rule_repeated_connection_failures,
    rule_large_outbound_transfer,
    rule_dns_burst,
]


def evaluate_event(event):
    """
    Run every detection rule against one event.

    Returns a list of alerts.
    """

    alerts = []

    for rule in RULES:
        try:
            result = rule(event)

            if result:
                alert = {
                    **result,
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "src_port": event.get("src_port"),
                    "dest_port": event.get("dest_port"),
                    "timestamp": event.get("ts"),
                    "service": event.get("service"),
                    "proto": event.get("proto"),
                    "tactic": event.get("tactic"),
                }

                alerts.append(alert)

        except Exception as error:
            print(f"Rule error in {rule.__name__}: {error}")

    return alerts