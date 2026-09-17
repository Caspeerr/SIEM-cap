import json
import time
from kafka import KafkaProducer


# ============================================================
# CONFIGURATION
# ============================================================

KAFKA_SERVER = "localhost:9092"
TOPIC = "zeekdata-stream"


producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)


def send_event(event):
    """Send one event to Kafka."""
    producer.send(TOPIC, event)
    producer.flush()

    print(
        f"  SENT: {event.get('src_ip')} -> "
        f"{event.get('dest_ip')}:{event.get('dest_port')} "
        f"| service={event.get('service')} "
        f"| state={event.get('conn_state')}"
    )


# ============================================================
# RULE 1 — PORT SCAN
# ============================================================

def test_port_scan():
    print("\n" + "=" * 70)
    print("TEST 1: PORT SCAN")
    print("=" * 70)

    print(
        "\nExpected detection:"
        "\n  Rule ID: PORT_SCAN_001"
        "\n  Rule: Possible Port Scan"
        "\n  Severity: HIGH"
        "\n"
        "\nWhy:"
        "\n  The same source IP will contact 11 different destination"
        "\n  ports within a 30-second event-time window."
    )

    base_time = time.time()

    src_ip = "192.168.10.50"
    dest_ip = "192.168.10.100"

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
        3389,
    ]

    print("\nSending port-scan pattern...")

    for i, port in enumerate(ports):

        event = {
            "ts": base_time + i,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": 40000 + i,
            "dest_port": port,
            "proto": "tcp",
            "service": "unknown",
            "conn_state": "S0",
            "tactic": "Discovery",
            "source_release": "SIEM-Test-Injection",
        }

        send_event(event)

    print("\nExpected result:")
    print("  ✓ PORT_SCAN_001 should be generated")


# ============================================================
# RULE 2 — REPEATED CONNECTION FAILURES
# ============================================================

def test_brute_force():
    print("\n" + "=" * 70)
    print("TEST 2: REPEATED CONNECTION FAILURES")
    print("=" * 70)

    print(
        "\nExpected detection:"
        "\n  Rule ID: BRUTE_FORCE_001"
        "\n  Rule: Repeated Connection Failures"
        "\n  Severity: HIGH"
        "\n"
        "\nWhy:"
        "\n  The same source will make 6 failed connections to"
        "\n  the same destination IP and destination port within 60 seconds."
    )

    base_time = time.time() + 100

    src_ip = "192.168.20.50"
    dest_ip = "192.168.20.100"
    dest_port = 22

    print("\nSending repeated failed SSH connections...")

    for i in range(6):

        event = {
            "ts": base_time + i,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": 41000 + i,
            "dest_port": dest_port,
            "proto": "tcp",
            "service": "ssh",
            "conn_state": "REJ",
            "tactic": "Credential_Access",
            "source_release": "SIEM-Test-Injection",
        }

        send_event(event)

    print("\nExpected result:")
    print("  ✓ BRUTE_FORCE_001 should be generated")


# ============================================================
# RULE 3 — LARGE OUTBOUND TRANSFER
# ============================================================

def test_exfiltration():
    print("\n" + "=" * 70)
    print("TEST 3: LARGE OUTBOUND TRANSFER")
    print("=" * 70)

    print(
        "\nExpected detection:"
        "\n  Rule ID: EXFIL_001"
        "\n  Rule: Large Outbound Transfer"
        "\n  Severity: MEDIUM"
        "\n"
        "\nWhy:"
        "\n  One connection will contain more than 1 MB of"
        "\n  outbound data."
    )

    event = {
        "ts": time.time() + 200,
        "src_ip": "192.168.30.50",
        "dest_ip": "203.0.113.50",
        "src_port": 45000,
        "dest_port": 443,
        "proto": "tcp",
        "service": "https",
        "conn_state": "SF",

        # 2 MB
        "orig_bytes": 2_000_000,

        "resp_bytes": 5000,
        "orig_pkts": 2000,
        "resp_pkts": 20,

        "tactic": "Exfiltration",
        "source_release": "SIEM-Test-Injection",
    }

    print("\nSending large outbound transfer event...")

    send_event(event)

    print("\nExpected result:")
    print("  ✓ EXFIL_001 should be generated")


# ============================================================
# RULE 4 — DNS BURST
# ============================================================

def test_dns_burst():
    print("\n" + "=" * 70)
    print("TEST 4: DNS ACTIVITY BURST")
    print("=" * 70)

    print(
        "\nExpected detection:"
        "\n  Rule ID: DNS_BURST_001"
        "\n  Rule: DNS Activity Burst"
        "\n  Severity: MEDIUM"
        "\n"
        "\nWhy:"
        "\n  The same source IP will generate 16 DNS connections"
        "\n  within a 30-second event-time window."
    )

    base_time = time.time() + 300

    src_ip = "192.168.40.50"
    dest_ip = "8.8.8.8"

    print("\nSending DNS burst...")

    for i in range(16):

        event = {
            "ts": base_time + i,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": 50000 + i,
            "dest_port": 53,
            "proto": "udp",
            "service": "dns",
            "conn_state": "SF",

            "orig_bytes": 100,
            "resp_bytes": 200,

            "tactic": "Command_and_Control",
            "source_release": "SIEM-Test-Injection",
        }

        send_event(event)

    print("\nExpected result:")
    print("  ✓ DNS_BURST_001 should be generated")


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print(" SENTINELSTREAM — SECURITY RULE INJECTION TEST")
    print("=" * 70)

    print("\nKafka:")
    print(f"  Server: {KAFKA_SERVER}")
    print(f"  Topic:  {TOPIC}")

    print("\nThis test will generate events for ALL FOUR rules:")
    print("  1. PORT_SCAN_001")
    print("  2. BRUTE_FORCE_001")
    print("  3. EXFIL_001")
    print("  4. DNS_BURST_001")

    print("\nStarting tests...")

    test_port_scan()

    test_brute_force()

    test_exfiltration()

    test_dns_burst()

    producer.flush()

    print("\n")
    print("=" * 70)
    print("ALL TEST EVENTS SENT")
    print("=" * 70)

    print(
        "\nCheck your FastAPI terminal."
        "\nYou should see 'Received:' followed by 'ALERT:' messages."
    )

    print(
        "\nThen check the SentinelStream frontend."
        "\nThe generated alerts should appear in your Alerts section."
    )

    producer.close()


if __name__ == "__main__":
    main()