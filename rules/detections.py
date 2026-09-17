from collections import defaultdict, deque


# ============================================================
# RULE STATE
# ============================================================
# These structures remember recent events so that the SIEM can
# detect behavior/patterns over time instead of judging only
# one event at a time.
# ============================================================


# ------------------------------------------------------------
# RULE 1: PORT SCAN
# ------------------------------------------------------------
# { src_ip: deque of (event_time, dest_port) }
_port_history = defaultdict(deque)

PORT_SCAN_WINDOW_SECONDS = 30
PORT_SCAN_THRESHOLD = 10

# Prevent the same source from generating the same port-scan
# alert repeatedly during the same detection window.
_port_scan_alerted = set()


# ------------------------------------------------------------
# RULE 2: REPEATED CONNECTION FAILURES
# ------------------------------------------------------------
# { (src_ip, dest_ip, dest_port): deque of event_time }
_failed_conn_history = defaultdict(deque)

FAILED_CONN_WINDOW_SECONDS = 60
FAILED_CONN_THRESHOLD = 5

# Zeek connection states indicating rejected/incomplete attempts.
FAILED_STATES = {
    "REJ",
    "S0",
    "RSTO",
    "RSTR",
}

_failed_alerted = set()


# ------------------------------------------------------------
# RULE 3: LARGE OUTBOUND TRANSFER
# ------------------------------------------------------------
# 1 MB threshold for one connection.
EXFIL_BYTES_THRESHOLD = 1_000_000


# ------------------------------------------------------------
# RULE 4: DNS BURST
# ------------------------------------------------------------
# { src_ip: deque of event_time }
_dns_history = defaultdict(deque)

DNS_BURST_WINDOW_SECONDS = 30
DNS_BURST_THRESHOLD = 15

_dns_burst_alerted = set()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _get_event_time(event):
    """
    Get the timestamp belonging to the event itself.

    Historical Zeek data may be replayed very quickly, so using
    time.time() would make detection windows inaccurate.

    The event timestamp is therefore used instead.
    """

    ts = event.get("ts")

    try:
        return float(ts)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value):
    """
    Safely convert a value to an integer.
    """

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


# ============================================================
# RULE 1
# POSSIBLE PORT SCAN
# ============================================================

def rule_port_scan(event):
    """
    Detect possible port scanning.

    A source IP must contact more than 10 DISTINCT destination
    ports within 30 seconds.

    This is more meaningful than simply checking whether a
    connection uses a commonly targeted port.
    """

    src_ip = event.get("src_ip")
    dest_port = _safe_int(event.get("dest_port"))

    if not src_ip or dest_port is None:
        return None

    now = _get_event_time(event)

    history = _port_history[src_ip]

    history.append((now, dest_port))

    # Remove events outside the detection window.
    while history and now - history[0][0] > PORT_SCAN_WINDOW_SECONDS:
        history.popleft()

    unique_ports = {
        port
        for _, port in history
    }

    if len(unique_ports) > PORT_SCAN_THRESHOLD:

        alert_key = (
            src_ip,
            tuple(sorted(unique_ports)),
        )

        if alert_key in _port_scan_alerted:
            return None

        _port_scan_alerted.add(alert_key)

        return {
            "rule_id": "PORT_SCAN_001",
            "rule_name": "Possible Port Scan",
            "severity": "HIGH",
            "description": (
                f"{src_ip} contacted {len(unique_ports)} "
                f"distinct destination ports within "
                f"{PORT_SCAN_WINDOW_SECONDS} seconds"
            ),
        }

    return None


# ============================================================
# RULE 2
# REPEATED CONNECTION FAILURES
# ============================================================

def rule_repeated_connection_failures(event):
    """
    Detect repeated failed/rejected connection attempts.

    The same source must repeatedly target the same destination
    IP and destination port.

    This can indicate:
      - brute-force attempts
      - service probing
      - repeated connection attempts
      - automated attack activity
    """

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = _safe_int(event.get("dest_port"))
    conn_state = str(event.get("conn_state", "")).upper()

    if conn_state not in FAILED_STATES:
        return None

    if not src_ip or not dest_ip or dest_port is None:
        return None

    now = _get_event_time(event)

    key = (
        src_ip,
        dest_ip,
        dest_port,
    )

    history = _failed_conn_history[key]

    history.append(now)

    # Remove events older than 60 seconds.
    while history and now - history[0] > FAILED_CONN_WINDOW_SECONDS:
        history.popleft()

    # More than 5 failures = 6 or more attempts.
    if len(history) > FAILED_CONN_THRESHOLD:

        if key in _failed_alerted:
            return None

        _failed_alerted.add(key)

        return {
            "rule_id": "BRUTE_FORCE_001",
            "rule_name": "Repeated Connection Failures",
            "severity": "HIGH",
            "description": (
                f"{src_ip} generated {len(history)} "
                f"failed/rejected connections to "
                f"{dest_ip}:{dest_port} within "
                f"{FAILED_CONN_WINDOW_SECONDS} seconds"
            ),
        }

    return None


# ============================================================
# RULE 3
# LARGE OUTBOUND TRANSFER
# ============================================================

def rule_large_outbound_transfer(event):
    """
    Detect a potentially suspiciously large outbound transfer.

    The rule checks orig_bytes because in Zeek connection logs
    orig_bytes represents bytes sent by the originator.

    This is a threshold-based detection and should be treated
    as a potential indicator of data exfiltration rather than
    proof of exfiltration.
    """

    orig_bytes = event.get("orig_bytes")

    try:
        orig_bytes = float(orig_bytes)
    except (TypeError, ValueError):
        return None

    if orig_bytes <= EXFIL_BYTES_THRESHOLD:
        return None

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")

    return {
        "rule_id": "EXFIL_001",
        "rule_name": "Large Outbound Transfer",
        "severity": "MEDIUM",
        "description": (
            f"{src_ip} sent {int(orig_bytes):,} bytes "
            f"to {dest_ip} in a single connection"
        ),
    }


# ============================================================
# RULE 4
# DNS ACTIVITY BURST
# ============================================================

def rule_dns_burst(event):
    """
    Detect unusually high DNS activity from one source.

    Normal systems make DNS requests, so a single DNS request
    should NOT generate an alert.

    An alert is generated only when the same source generates
    more than 15 DNS connections within 30 seconds.

    This can indicate:
      - automated DNS lookups
      - DNS tunneling
      - malware beaconing
      - suspicious automated activity
    """

    src_ip = event.get("src_ip")

    service = str(
        event.get("service", "")
    ).lower()

    dest_port = _safe_int(
        event.get("dest_port")
    )

    is_dns = (
        service == "dns"
        or dest_port == 53
    )

    if not is_dns or not src_ip:
        return None

    now = _get_event_time(event)

    history = _dns_history[src_ip]

    history.append(now)

    # Remove DNS events older than 30 seconds.
    while history and now - history[0] > DNS_BURST_WINDOW_SECONDS:
        history.popleft()

    if len(history) > DNS_BURST_THRESHOLD:

        if src_ip in _dns_burst_alerted:
            return None

        _dns_burst_alerted.add(src_ip)

        return {
            "rule_id": "DNS_BURST_001",
            "rule_name": "DNS Activity Burst",
            "severity": "MEDIUM",
            "description": (
                f"{src_ip} generated {len(history)} "
                f"DNS connections within "
                f"{DNS_BURST_WINDOW_SECONDS} seconds"
            ),
        }

    return None


# ============================================================
# OPTIONAL STATE CLEANUP
# ============================================================

def clear_detection_state():
    """
    Clear all state maintained by the detection rules.

    Useful when restarting/replaying a dataset during testing.
    """

    _port_history.clear()
    _failed_conn_history.clear()
    _dns_history.clear()

    _port_scan_alerted.clear()
    _failed_alerted.clear()
    _dns_burst_alerted.clear()