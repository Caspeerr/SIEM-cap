from collections import defaultdict, deque
from ipaddress import ip_address

# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# RULE 1: BRUTE FORCE / REPEATED CONNECTION FAILURES
# ------------------------------------------------------------

BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 8

FAILED_STATES = {
    "REJ",
    "S0",
    "RSTO",
    "RSTR",
}


# ------------------------------------------------------------
# RULE 2: PORT SCAN
# ------------------------------------------------------------

PORT_SCAN_WINDOW_SECONDS = 30
PORT_SCAN_THRESHOLD = 15


# ------------------------------------------------------------
# RULE 3: LARGE OUTBOUND TRANSFER
# ------------------------------------------------------------

# 50 MB
LARGE_TRANSFER_BYTES = 50 * 1024 * 1024


# ------------------------------------------------------------
# RULE 4: DNS BURST / POSSIBLE DNS TUNNELING
# ------------------------------------------------------------

DNS_BURST_WINDOW_SECONDS = 30
DNS_BURST_THRESHOLD = 25


# ============================================================
# STATE
# ============================================================

# (src_ip, dest_ip, dest_port) -> timestamps
_failed_connection_history = defaultdict(deque)

# src_ip -> (timestamp, destination_port)
_port_history = defaultdict(deque)

# src_ip -> DNS timestamps
_dns_history = defaultdict(deque)


# ============================================================
# HELPERS
# ============================================================

def _event_time(event):
    """
    Return the timestamp supplied by the telemetry.

    We intentionally use the event timestamp rather than
    time.time() so replayed Zeek datasets behave correctly.
    """
    try:
        return float(event.get("ts", 0))
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_private_ip(value):
    """
    Determine whether an IP belongs to a private/internal range.
    """
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


# ============================================================
# RULE 1
# BRUTE FORCE / REPEATED CONNECTION FAILURES
# ============================================================

def rule_brute_force(event):
    """
    Detect repeated failed/incomplete connections from the same
    source to the same destination service.

    This is intentionally connection-oriented because Zeek's
    conn.log provides useful state information such as:

        REJ
        S0
        RSTO
        RSTR
    """

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = _safe_int(event.get("dest_port"))
    conn_state = str(event.get("conn_state", "")).upper()

    if not src_ip or not dest_ip or dest_port is None:
        return None

    if conn_state not in FAILED_STATES:
        return None

    timestamp = _event_time(event)

    key = (src_ip, dest_ip, dest_port)

    history = _failed_connection_history[key]
    history.append(timestamp)

    # Remove events outside the detection window.
    while history and timestamp - history[0] > BRUTE_FORCE_WINDOW_SECONDS:
        history.popleft()

    if len(history) < BRUTE_FORCE_THRESHOLD:
        return None

    service = event.get("service") or "unknown"

    return {
        "rule_id": "BRUTE_FORCE_001",
        "rule_name": "Repeated Authentication/Connection Failures",
        "severity": "HIGH",
        "description": (
            f"{src_ip} generated {len(history)} failed or incomplete "
            f"connections to {dest_ip}:{dest_port} "
            f"within {BRUTE_FORCE_WINDOW_SECONDS} seconds"
        ),
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
        "evidence": {
            "failed_attempts": len(history),
            "window_seconds": BRUTE_FORCE_WINDOW_SECONDS,
            "connection_state": conn_state,
            "service": service,
        },
    }


# ============================================================
# RULE 2
# PORT SCANNING
# ============================================================

def rule_port_scan(event):
    """
    Detect horizontal/vertical port scanning behaviour.

    A source contacting many distinct destination ports within
    a short period is suspicious.

    The rule requires DISTINCT destination ports so repeated
    connections to one service do not become a port-scan alert.
    """

    src_ip = event.get("src_ip")
    dest_port = _safe_int(event.get("dest_port"))

    if not src_ip or dest_port is None:
        return None

    timestamp = _event_time(event)

    history = _port_history[src_ip]
    history.append((timestamp, dest_port))

    while history and timestamp - history[0][0] > PORT_SCAN_WINDOW_SECONDS:
        history.popleft()

    unique_ports = {port for _, port in history}

    if len(unique_ports) < PORT_SCAN_THRESHOLD:
        return None

    return {
        "rule_id": "PORT_SCAN_001",
        "rule_name": "Potential Port Scan",
        "severity": "HIGH",
        "description": (
            f"{src_ip} contacted {len(unique_ports)} distinct "
            f"destination ports within "
            f"{PORT_SCAN_WINDOW_SECONDS} seconds"
        ),
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "evidence": {
            "unique_destination_ports": len(unique_ports),
            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
        },
    }


# ============================================================
# RULE 3
# LARGE OUTBOUND DATA TRANSFER
# ============================================================

def rule_large_outbound_transfer(event):
    """
    Detect unusually large outbound transfers.

    This rule uses Zeek's orig_bytes field.

    It is deliberately a threshold-based detection rather than
    claiming that every large transfer is exfiltration.
    """

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")

    if not src_ip or not dest_ip:
        return None

    orig_bytes = _safe_float(event.get("orig_bytes"))

    if orig_bytes is None:
        return None

    if orig_bytes < LARGE_TRANSFER_BYTES:
        return None

    # Only classify this as outbound when the source appears
    # internal and the destination appears external.
    if not _is_private_ip(src_ip):
        return None

    if _is_private_ip(dest_ip):
        return None

    megabytes = orig_bytes / (1024 * 1024)

    return {
        "rule_id": "EXFIL_001",
        "rule_name": "Large Outbound Data Transfer",
        "severity": "HIGH",
        "description": (
            f"Internal host {src_ip} transferred approximately "
            f"{megabytes:.2f} MB to external host {dest_ip}"
        ),
        "mitre_technique": "T1041",
        "mitre_tactic": "Exfiltration",
        "evidence": {
            "orig_bytes": int(orig_bytes),
            "megabytes": round(megabytes, 2),
            "internal_source": True,
            "external_destination": True,
        },
    }


# ============================================================
# RULE 4
# DNS BURST / POSSIBLE DNS TUNNELING
# ============================================================

def rule_dns_burst(event):
    """
    Detect unusually frequent DNS connections from a single
    source.

    This is a behavioural indicator. It does not claim that
    DNS traffic is malicious by itself.
    """

    src_ip = event.get("src_ip")
    service = str(event.get("service", "")).lower()
    dest_port = _safe_int(event.get("dest_port"))

    if not src_ip:
        return None

    is_dns = (
        service == "dns"
        or dest_port == 53
    )

    if not is_dns:
        return None

    timestamp = _event_time(event)

    history = _dns_history[src_ip]
    history.append(timestamp)

    while history and timestamp - history[0] > DNS_BURST_WINDOW_SECONDS:
        history.popleft()

    if len(history) < DNS_BURST_THRESHOLD:
        return None

    return {
        "rule_id": "DNS_BURST_001",
        "rule_name": "Abnormal DNS Activity Burst",
        "severity": "MEDIUM",
        "description": (
            f"{src_ip} generated {len(history)} DNS connections "
            f"within {DNS_BURST_WINDOW_SECONDS} seconds"
        ),
        "mitre_technique": "T1071.004",
        "mitre_tactic": "Command and Control",
        "evidence": {
            "dns_connections": len(history),
            "window_seconds": DNS_BURST_WINDOW_SECONDS,
        },
    }


# ============================================================
# RESET FUNCTION
# ============================================================

def reset_detection_state():
    """
    Clear all stateful detection windows.

    Useful when starting a fresh replay/test session.
    """

    _failed_connection_history.clear()
    _port_history.clear()
    _dns_history.clear()