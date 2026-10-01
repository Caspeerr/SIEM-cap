from collections import defaultdict, deque
from ipaddress import ip_address
import math

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
AUTHENTICATION_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3389}


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

# ------------------------------------------------------------
# RULE 5: UNUSUAL DESTINATION PORT
# ------------------------------------------------------------

PORT_BASELINE_EVENTS = 100
RARE_PORT_MAX_SEEN = 2
COMMON_DESTINATION_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521,
    1900, 3306, 3389, 5432, 5900, 5353, 5355, 8080, 8443,
}
# ------------------------------------------------------------
# RULE 6: LONG-LIVED CONNECTION
# ------------------------------------------------------------

LONG_CONNECTION_SECONDS = 3600

# ------------------------------------------------------------
# RULE 7: HIGH CONNECTION RATE
# ------------------------------------------------------------

CONNECTION_RATE_WINDOW_SECONDS = 10
CONNECTION_RATE_THRESHOLD = 100

# ------------------------------------------------------------
# RULE 8: PERIODIC CONNECTION BEACON
# ------------------------------------------------------------

BEACON_MIN_CONNECTIONS = 5
BEACON_MIN_INTERVAL_SECONDS = 10
BEACON_MAX_INTERVAL_SECONDS = 3600


# ============================================================
# STATE
# ============================================================

# (src_ip, dest_ip, dest_port) -> timestamps
_failed_connection_history = defaultdict(deque)
_failed_connection_alerted = set()

# (src_ip, dest_ip) -> (timestamp, destination_port)
_port_history = defaultdict(deque)
_port_scan_alerted = set()

# src_ip -> DNS timestamps
_dns_history = defaultdict(deque)
_dns_burst_alerted = set()

_observed_connection_count = 0
_destination_port_counts = defaultdict(int)
_unusual_port_alerted = set()
_connection_rate_history = defaultdict(deque)
_connection_rate_alerted = set()
_beacon_history = defaultdict(lambda: deque(maxlen=BEACON_MIN_CONNECTIONS))
_beacon_alerted = set()


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
        parsed = float(value)
        return parsed if math.isfinite(parsed) else None
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

    if conn_state not in FAILED_STATES or dest_port not in AUTHENTICATION_PORTS:
        return None

    timestamp = _event_time(event)

    key = (src_ip, dest_ip, dest_port)

    history = _failed_connection_history[key]
    history.append(timestamp)

    # Remove events outside the detection window.
    while history and timestamp - history[0] > BRUTE_FORCE_WINDOW_SECONDS:
        history.popleft()

    if len(history) < BRUTE_FORCE_THRESHOLD:
        _failed_connection_alerted.discard(key)
        return None

    if key in _failed_connection_alerted:
        return None

    _failed_connection_alerted.add(key)

    service = event.get("service") or "unknown"

    return {
        "rule_id": "BRUTE_FORCE_001",
        "rule_name": "Repeated Rejected Authentication-Service Connections",
        "severity": "HIGH",
        "description": (
            f"{src_ip} received {len(history)} rejected connections to "
            f"authentication service {dest_ip}:{dest_port} "
            f"within {BRUTE_FORCE_WINDOW_SECONDS} seconds; this is not proof "
            "of failed logins"
        ),
        "mitre_technique": None,
        "mitre_tactic": None,
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

    dest_ip = event.get("dest_ip")
    if not dest_ip:
        return None

    key = (src_ip, dest_ip)
    history = _port_history[key]
    history.append((timestamp, dest_port))

    while history and timestamp - history[0][0] > PORT_SCAN_WINDOW_SECONDS:
        history.popleft()

    unique_ports = {port for _, port in history}

    if len(unique_ports) < PORT_SCAN_THRESHOLD:
        _port_scan_alerted.discard(key)
        return None

    if key in _port_scan_alerted:
        return None

    _port_scan_alerted.add(key)

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
        _dns_burst_alerted.discard(src_ip)
        return None

    if src_ip in _dns_burst_alerted:
        return None

    _dns_burst_alerted.add(src_ip)

    return {
        "rule_id": "DNS_BURST_001",
        "rule_name": "High-Volume DNS Activity",
        "severity": "LOW",
        "description": (
            f"{src_ip} generated {len(history)} DNS connections "
            f"within {DNS_BURST_WINDOW_SECONDS} seconds"
        ),
        "mitre_technique": None,
        "mitre_tactic": None,
        "evidence": {
            "dns_connections": len(history),
            "window_seconds": DNS_BURST_WINDOW_SECONDS,
        },
    }


# ============================================================
# RULE 5
# UNUSUAL DESTINATION PORT
# ============================================================

def rule_unusual_destination_port(event):
    """
    Flag an uncommon destination port after enough network traffic has
    been observed to form a simple baseline.

    The rule counts TCP/UDP destination ports across the stream and flags
    non-standard ports seen no more than RARE_PORT_MAX_SEEN times. Common
    service ports are excluded. Rarity alone is an investigation signal,
    not evidence that a connection is malicious.
    """
    global _observed_connection_count

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = _safe_int(event.get("dest_port"))
    proto = str(event.get("proto", "")).lower()
    if (
        not src_ip
        or not dest_ip
        or dest_port is None
        or not 1 <= dest_port <= 65535
        or proto not in {"tcp", "udp"}
    ):
        return None

    _observed_connection_count += 1
    _destination_port_counts[dest_port] += 1
    observed = _destination_port_counts[dest_port]
    key = (src_ip, dest_ip, dest_port)
    if (
        _observed_connection_count < PORT_BASELINE_EVENTS
        or dest_port in COMMON_DESTINATION_PORTS
        or observed > RARE_PORT_MAX_SEEN
        or key in _unusual_port_alerted
    ):
        return None

    _unusual_port_alerted.add(key)
    return {
        "rule_id": "UNUSUAL_PORT_001",
        "rule_name": "Rare Destination Port",
        "severity": "MEDIUM",
        "description": (
            f"{src_ip} connected to {dest_ip}:{dest_port}, a destination port "
            "seen infrequently in the observed traffic baseline"
        ),
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "evidence": {
            "destination_port": dest_port,
            "port_observations": observed,
            "baseline_connections": _observed_connection_count,
        },
    }


# ============================================================
# RULE 6
# LONG-LIVED CONNECTION
# ============================================================

def rule_long_connection(event):
    """
    Flag a successfully established connection lasting at least one hour.

    The decision uses Zeek's duration and connection state fields. Long
    sessions can be legitimate, so the alert is a review signal rather
    than a claim that the flow is command-and-control traffic.
    """
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    duration = _safe_float(event.get("duration"))
    conn_state = str(event.get("conn_state", "")).upper()
    if (
        not src_ip
        or not dest_ip
        or duration is None
        or duration < LONG_CONNECTION_SECONDS
        or conn_state not in {"SF", "S1", "S2", "S3"}
    ):
        return None

    return {
        "rule_id": "LONG_CONNECTION_001",
        "rule_name": "Long-Lived Established Connection",
        "severity": "MEDIUM",
        "description": (
            f"{src_ip} maintained an established connection to {dest_ip} "
            f"for {duration / 3600:.1f} hours"
        ),
        "mitre_technique": "T1071",
        "mitre_tactic": "Command and Control",
        "evidence": {
            "duration_seconds": duration,
            "connection_state": conn_state,
        },
    }


# ============================================================
# RULE 7
# HIGH CONNECTION RATE / POSSIBLE FLOODING
# ============================================================

def rule_connection_flood(event):
    """
    Detect a source initiating many connections in a short rolling window.

    Connections are grouped by source IP and measured using event
    timestamps. The alert includes the number of connections and distinct
    destinations to help distinguish broad flooding from concentrated
    traffic. High rate alone does not prove a denial-of-service attack.
    """
    src_ip = event.get("src_ip")
    if not src_ip:
        return None

    timestamp = _event_time(event)
    history = _connection_rate_history[src_ip]
    history.append((timestamp, event.get("dest_ip")))
    while history and timestamp - history[0][0] > CONNECTION_RATE_WINDOW_SECONDS:
        history.popleft()

    if len(history) < CONNECTION_RATE_THRESHOLD:
        _connection_rate_alerted.discard(src_ip)
        return None
    if src_ip in _connection_rate_alerted:
        return None

    _connection_rate_alerted.add(src_ip)
    destinations = {dest_ip for _, dest_ip in history if dest_ip}
    return {
        "rule_id": "CONNECTION_FLOOD_001",
        "rule_name": "High Source Connection Rate",
        "severity": "HIGH",
        "description": (
            f"{src_ip} initiated {len(history)} connections within "
            f"{CONNECTION_RATE_WINDOW_SECONDS} seconds"
        ),
        "mitre_technique": "T1498",
        "mitre_tactic": "Impact",
        "evidence": {
            "connections": len(history),
            "unique_destinations": len(destinations),
            "window_seconds": CONNECTION_RATE_WINDOW_SECONDS,
        },
    }


# ============================================================
# RULE 8
# PERIODIC CONNECTION BEACON
# ============================================================

def rule_periodic_beacon(event):
    """
    Detect successful connections to one destination at regular intervals.

    The rule groups by source IP, destination IP, and destination port,
    then compares the latest connection intervals. It requires a minimum
    number of connections, a plausible interval range, and low interval
    spread. Scheduled or otherwise legitimate traffic can also be regular.
    """
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = _safe_int(event.get("dest_port"))
    conn_state = str(event.get("conn_state", "")).upper()
    if not src_ip or not dest_ip or dest_port is None or conn_state != "SF":
        return None

    key = (src_ip, dest_ip, dest_port)
    history = _beacon_history[key]
    history.append(_event_time(event))
    if len(history) < BEACON_MIN_CONNECTIONS:
        return None

    timestamps = list(history)
    intervals = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
    average_interval = sum(intervals) / len(intervals)
    spread = max(intervals) - min(intervals)
    tolerance = max(2.0, average_interval * 0.2)
    is_periodic = (
        BEACON_MIN_INTERVAL_SECONDS <= average_interval <= BEACON_MAX_INTERVAL_SECONDS
        and spread <= tolerance
    )

    if not is_periodic:
        _beacon_alerted.discard(key)
        return None
    if key in _beacon_alerted:
        return None

    _beacon_alerted.add(key)
    return {
        "rule_id": "PERIODIC_BEACON_001",
        "rule_name": "Regular Repeated Connections",
        "severity": "MEDIUM",
        "description": (
            f"{src_ip} connected to {dest_ip}:{dest_port} at regular "
            f"intervals averaging {average_interval:.1f} seconds"
        ),
        "mitre_technique": "T1071",
        "mitre_tactic": "Command and Control",
        "evidence": {
            "connection_count": len(history),
            "average_interval_seconds": round(average_interval, 2),
            "interval_spread_seconds": round(spread, 2),
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

    global _observed_connection_count

    _failed_connection_history.clear()
    _port_history.clear()
    _dns_history.clear()
    _destination_port_counts.clear()
    _connection_rate_history.clear()
    _beacon_history.clear()
    _failed_connection_alerted.clear()
    _port_scan_alerted.clear()
    _dns_burst_alerted.clear()
    _unusual_port_alerted.clear()
    _connection_rate_alerted.clear()
    _beacon_alerted.clear()
    _observed_connection_count = 0