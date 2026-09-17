from collections import defaultdict, deque

# ============================================
# STATE the rules remember as events flow through
# (this is what lets us detect PATTERNS over time,
#  not just judge one event in isolation)
# ============================================

# Rule 1 state: which ports has each src_ip hit recently?
# { src_ip: deque of (event_time, dest_port) }
_port_history = defaultdict(deque)
PORT_SCAN_WINDOW_SECONDS = 30
PORT_SCAN_THRESHOLD = 10  # more than 10 DISTINCT ports in the window = alert

# Rule 2 state: how many failed/rejected connections has src_ip sent to this target?
# { (src_ip, dest_ip, dest_port): deque of event_time }
_failed_conn_history = defaultdict(deque)
FAILED_CONN_WINDOW_SECONDS = 60
FAILED_CONN_THRESHOLD = 5  # more than 5 failures in the window = alert

# connection states that represent a rejected / incomplete connection
# (these are Zeek's real conn_state codes, not invented)
FAILED_STATES = {"REJ", "S0", "RSTO", "RSTR"}

# Rule 3: no state needed, judged per-event
EXFIL_BYTES_THRESHOLD = 1_000_000  # 1MB+ sent out in a single connection

# Rule 4 state: how many DNS connections has src_ip made recently?
# (a burst of DNS activity can indicate tunneling / automated lookups, not normal browsing)
_dns_history = defaultdict(deque)
DNS_BURST_WINDOW_SECONDS = 30
DNS_BURST_THRESHOLD = 15  # more than 15 DNS connections in the window = alert


def _get_event_time(event):
    """
    Use the event's OWN timestamp field (real event time), not wall-clock time.
    This makes the windows correct even when replaying sped-up historical data,
    since we're measuring gaps between real event times, not real-world seconds.
    """
    ts = event.get("ts")
    try:
        return float(ts)
    except (TypeError, ValueError):
        return 0.0


def rule_port_scan(event):
    """
    Detect possible port scanning: one source IP contacting many
    DIFFERENT destination ports within a short time window.
    """
    src_ip = event.get("src_ip")
    dest_port = event.get("dest_port")
    if not src_ip or dest_port is None:
        return None

    now = _get_event_time(event)
    history = _port_history[src_ip]
    history.append((now, dest_port))

    # drop anything older than our window
    while history and now - history[0][0] > PORT_SCAN_WINDOW_SECONDS:
        history.popleft()

    unique_ports = {port for _, port in history}

    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        return {
            "rule_id": "PORT_SCAN_001",
            "rule_name": "Possible Port Scan",
            "severity": "HIGH",
            "description": f"{src_ip} contacted {len(unique_ports)} distinct ports "
                            f"within {PORT_SCAN_WINDOW_SECONDS}s",
        }
    return None


def rule_repeated_connection_failures(event):
    """
    Detect possible brute force / probing: many failed or rejected
    connection attempts from the same source to the same target.
    """
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = event.get("dest_port")
    conn_state = event.get("conn_state")

    if conn_state not in FAILED_STATES:
        return None
    if not src_ip or not dest_ip or dest_port is None:
        return None

    now = _get_event_time(event)
    key = (src_ip, dest_ip, dest_port)
    history = _failed_conn_history[key]
    history.append(now)

    while history and now - history[0] > FAILED_CONN_WINDOW_SECONDS:
        history.popleft()

    if len(history) > FAILED_CONN_THRESHOLD:
        return {
            "rule_id": "BRUTE_FORCE_001",
            "rule_name": "Repeated Connection Failures",
            "severity": "HIGH",
            "description": f"{src_ip} had {len(history)} failed/rejected connections "
                            f"to {dest_ip}:{dest_port} within {FAILED_CONN_WINDOW_SECONDS}s",
        }
    return None


def rule_large_outbound_transfer(event):
    """
    Detect possible data exfiltration: an unusually large amount
    of data sent OUT in a single connection.
    """
    orig_bytes = event.get("orig_bytes")
    try:
        orig_bytes = float(orig_bytes)
    except (TypeError, ValueError):
        return None

    if orig_bytes > EXFIL_BYTES_THRESHOLD:
        return {
            "rule_id": "EXFIL_001",
            "rule_name": "Large Outbound Transfer",
            "severity": "MEDIUM",
            "description": f"{event.get('src_ip')} sent {int(orig_bytes):,} bytes "
                            f"to {event.get('dest_ip')} in a single connection",
        }
    return None


def rule_dns_burst(event):
    """
    Detect a burst of DNS activity from one source, which can indicate
    DNS tunneling or automated/malicious lookups rather than normal browsing.
    """
    src_ip = event.get("src_ip")
    service = str(event.get("service", "")).lower()
    dest_port = event.get("dest_port")

    is_dns = service == "dns" or dest_port == 53
    if not is_dns or not src_ip:
        return None

    now = _get_event_time(event)
    history = _dns_history[src_ip]
    history.append(now)

    while history and now - history[0] > DNS_BURST_WINDOW_SECONDS:
        history.popleft()

    if len(history) > DNS_BURST_THRESHOLD:
        return {
            "rule_id": "DNS_BURST_001",
            "rule_name": "DNS Activity Burst",
            "severity": "MEDIUM",
            "description": f"{src_ip} made {len(history)} DNS connections "
                            f"within {DNS_BURST_WINDOW_SECONDS}s",
        }
    return None