import json
import time

from kafka import KafkaProducer


# ============================================================
# KAFKA CONFIGURATION
# ============================================================

KAFKA_SERVER = "localhost:9092"
KAFKA_TOPIC = "zeekdata-stream"


producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
)


# ============================================================
# TEST CONFIGURATION
# ============================================================

BASE_TIMESTAMP = time.time()


def make_zeek_event(
    timestamp,
    src_ip,
    dest_ip,
    src_port,
    dest_port,
    proto="tcp",
    service=None,
    conn_state="SF",
    orig_bytes=100,
    resp_bytes=100,
):
    """
    Create a Zeek conn.log-style event.

    These fields intentionally resemble the records coming
    through the Docker/Zeek pipeline.
    """

    if service is None:
        if dest_port == 53:
            service = "dns"
        elif dest_port == 22:
            service = "ssh"
        elif dest_port == 443:
            service = "ssl"
        else:
            service = "-"

    return {
        "ts": timestamp,

        "src_ip": src_ip,
        "dest_ip": dest_ip,

        "src_port": src_port,
        "dest_port": dest_port,

        "proto": proto,
        "service": service,

        "conn_state": conn_state,

        "orig_pkts": 2,
        "resp_pkts": 0,

        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,

        "orig_ip_bytes": orig_bytes + 40,
        "resp_ip_bytes": resp_bytes + 40,

        "duration": 0.002,

        "local_orig": True,
        "local_resp": False,

        "missed_bytes": 0,

        "history": "S",

        "community_id": "1:test-community-id",

        "uid": f"TEST-{int(timestamp * 1000000)}",

        "datetime": time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z",
            time.gmtime(timestamp)
        ),

        # Metadata used by your SIEM pipeline.
        "tactic": "Benign",

        "source_release": "SIEM-Test-Injection",
    }


# ============================================================
# KAFKA SEND FUNCTION
# ============================================================

def send_event(event, description, expected_rule=None):
    """
    Send one event to Kafka and display exactly what it is testing.
    """

    print()
    print("=" * 70)
    print(description)

    if expected_rule:
        print(f"Expected detection: {expected_rule}")
    else:
        print("Expected detection: NONE")

    print("-" * 70)
    print("Sending:")

    print(json.dumps(event, indent=2))

    producer.send(
        KAFKA_TOPIC,
        value=event,
    )

    producer.flush()

    print("Sent to Kafka.")
    print("=" * 70)


# ============================================================
# TEST 1
# BRUTE FORCE
# ============================================================

def test_brute_force():
    """
    Generate repeated failed SSH connections from the same
    source to the same destination.

    Rule threshold:
        8 failed connections
        within 60 seconds
    """

    print()
    print()
    print("#" * 70)
    print("TEST 1/4 — BRUTE FORCE")
    print("#" * 70)

    src_ip = "10.0.10.50"
    dest_ip = "10.0.10.10"

    start_time = BASE_TIMESTAMP + 10

    for attempt in range(8):

        event_time = start_time + attempt * 5

        event = make_zeek_event(
            timestamp=event_time,

            src_ip=src_ip,
            dest_ip=dest_ip,

            src_port=40000 + attempt,
            dest_port=22,

            proto="tcp",
            service="ssh",

            # Failed/incomplete connection.
            conn_state="REJ",

            orig_bytes=0,
            resp_bytes=0,
        )

        send_event(
            event,

            description=(
                f"BRUTE FORCE ATTEMPT {attempt + 1}/8\n"
                f"{src_ip} -> {dest_ip}:22"
            ),

            expected_rule=(
                "BRUTE_FORCE_001"
                if attempt == 7
                else "NONE YET"
            ),
        )

        time.sleep(0.1)


# ============================================================
# TEST 2
# PORT SCAN
# ============================================================

def test_port_scan():
    """
    Generate connections to many distinct destination ports.

    Rule threshold:
        15 distinct ports
        within 30 seconds
    """

    print()
    print()
    print("#" * 70)
    print("TEST 2/4 — PORT SCAN")
    print("#" * 70)

    src_ip = "10.0.10.51"
    dest_ip = "10.0.10.100"

    start_time = BASE_TIMESTAMP + 100

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
    ]

    for index, dest_port in enumerate(ports):

        event = make_zeek_event(
            timestamp=start_time + index,

            src_ip=src_ip,
            dest_ip=dest_ip,

            src_port=41000 + index,
            dest_port=dest_port,

            proto="tcp",
            service="-",

            conn_state="S0",

            orig_bytes=0,
            resp_bytes=0,
        )

        send_event(
            event,

            description=(
                f"PORT SCAN PROBE {index + 1}/{len(ports)}\n"
                f"{src_ip} -> {dest_ip}:{dest_port}"
            ),

            expected_rule=(
                "PORT_SCAN_001"
                if index == len(ports) - 1
                else "NONE YET"
            ),
        )

        time.sleep(0.1)


# ============================================================
# TEST 3
# LARGE OUTBOUND TRANSFER
# ============================================================

def test_large_outbound_transfer():
    """
    Generate a large outbound connection.

    Rule threshold:
        50 MB
        internal source -> external destination
    """

    print()
    print()
    print("#" * 70)
    print("TEST 3/4 — LARGE OUTBOUND TRANSFER")
    print("#" * 70)

    event = make_zeek_event(
        timestamp=BASE_TIMESTAMP + 200,

        src_ip="10.0.10.52",

        # External/public destination.
        dest_ip="8.8.8.8",

        src_port=45000,
        dest_port=443,

        proto="tcp",
        service="ssl",

        conn_state="SF",

        # 75 MB.
        orig_bytes=75 * 1024 * 1024,

        resp_bytes=25000,
    )

    send_event(
        event,

        description=(
            "Internal host transferring a large amount of data "
            "to an external destination."
        ),

        expected_rule="EXFIL_001",
    )


# ============================================================
# TEST 4
# DNS BURST
# ============================================================

def test_dns_burst():
    """
    Generate many DNS connections from one source.

    Rule threshold:
        25 DNS connections
        within 30 seconds
    """

    print()
    print()
    print("#" * 70)
    print("TEST 4/4 — DNS ACTIVITY BURST")
    print("#" * 70)

    src_ip = "10.0.10.53"
    dest_ip = "10.0.10.1"

    start_time = BASE_TIMESTAMP + 300

    for index in range(25):

        event = make_zeek_event(
            timestamp=start_time + index,

            src_ip=src_ip,
            dest_ip=dest_ip,

            src_port=50000 + index,
            dest_port=53,

            proto="udp",
            service="dns",

            conn_state="S0",

            orig_bytes=78,
            resp_bytes=0,
        )

        send_event(
            event,

            description=(
                f"DNS CONNECTION {index + 1}/25\n"
                f"{src_ip} -> {dest_ip}:53"
            ),

            expected_rule=(
                "DNS_BURST_001"
                if index == 24
                else "NONE YET"
            ),
        )

        time.sleep(0.1)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("SENTINELSTREAM — SIEM RULE TEST INJECTION")
    print("=" * 70)

    print()
    print(f"Kafka broker : {KAFKA_SERVER}")
    print(f"Kafka topic  : {KAFKA_TOPIC}")

    print()
    print("This test will generate:")
    print()
    print("1. BRUTE_FORCE_001")
    print("2. PORT_SCAN_001")
    print("3. EXFIL_001")
    print("4. DNS_BURST_001")

    print()
    print("All events use Zeek-style connection telemetry.")
    print("Starting tests...")

    # --------------------------------------------------------
    # Run tests
    # --------------------------------------------------------

    test_brute_force()

    test_port_scan()

    test_large_outbound_transfer()

    test_dns_burst()

    # --------------------------------------------------------
    # Finish
    # --------------------------------------------------------

    producer.flush()

    print()
    print()
    print("=" * 70)
    print("ALL TEST EVENTS SENT")
    print("=" * 70)

    print()
    print("Expected rules:")
    print()
    print("  BRUTE_FORCE_001")
    print("  PORT_SCAN_001")
    print("  EXFIL_001")
    print("  DNS_BURST_001")
    print()


if __name__ == "__main__":
    main()