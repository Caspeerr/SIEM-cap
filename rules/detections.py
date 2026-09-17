def rule_port_scan(event):
    """
    Detect possible port scanning activity.
    """

    src_port = event.get("src_port")
    dest_port = event.get("dest_port")

    if src_port is None or dest_port is None:
        return None

    # Simple first-stage rule:
    # connection to commonly scanned ports
    suspicious_ports = {
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3389,  # RDP
    }

    if int(dest_port) in suspicious_ports:
        return {
            "rule_id": "PORT_SCAN_001",
            "rule_name": "Suspicious Port Access",
            "severity": "MEDIUM",
            "description": f"Connection to commonly targeted port {dest_port}",
        }

    return None


def rule_suspicious_dns(event):
    """
    Detect suspicious DNS activity.
    """

    service = str(event.get("service", "")).lower()
    dest_port = event.get("dest_port")

    if service == "dns" or dest_port == 53:
        return {
            "rule_id": "DNS_001",
            "rule_name": "DNS Activity Detected",
            "severity": "LOW",
            "description": "DNS traffic detected",
        }

    return None


def rule_high_risk_tactic(event):
    """
    Detect events classified with higher-risk tactics.
    """

    tactic = str(event.get("tactic", "")).lower()

    high_risk = {
        "credential_access",
        "credential-access",
        "persistence",
        "execution",
        "privilege_escalation",
        "privilege-escalation",
    }

    if tactic in high_risk:
        return {
            "rule_id": "TACTIC_001",
            "rule_name": "High Risk Security Tactic",
            "severity": "HIGH",
            "description": f"High-risk tactic detected: {event.get('tactic')}",
        }

    return None