import json
import time
from kafka import KafkaProducer


KAFKA_SERVER = "localhost:9092"
TOPIC = "zeekdata-stream"


producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
)


def send_test_event(name, event):
    print("\n" + "=" * 60)
    print(f"INJECTING: {name}")
    print("=" * 60)
    print(json.dumps(event, indent=2))

    producer.send(TOPIC, event)
    producer.flush()

    print("✓ Event sent to Kafka")

    time.sleep(2)


# ---------------------------------------------------------
# TEST 1 — PORT SCAN / SUSPICIOUS PORT
# ---------------------------------------------------------

port_scan_event = {
    "ts": time.time(),
    "src_ip": "10.10.10.50",
    "dest_ip": "10.10.10.100",
    "src_port": 45678,
    "dest_port": 22,
    "proto": "tcp",
    "service": "ssh",
    "conn_state": "S0",
    "tactic": "Benign",
    "source_release": "SIEM-Test-Injection",
}


# ---------------------------------------------------------
# TEST 2 — DNS ACTIVITY
# ---------------------------------------------------------

dns_event = {
    "ts": time.time(),
    "src_ip": "10.10.10.51",
    "dest_ip": "8.8.8.8",
    "src_port": 51234,
    "dest_port": 53,
    "proto": "udp",
    "service": "dns",
    "conn_state": "SF",
    "tactic": "Benign",
    "source_release": "SIEM-Test-Injection",
}


# ---------------------------------------------------------
# TEST 3 — HIGH-RISK SECURITY TACTIC
# ---------------------------------------------------------

high_risk_event = {
    "ts": time.time(),
    "src_ip": "10.10.10.52",
    "dest_ip": "10.10.10.200",
    "src_port": 49821,
    "dest_port": 443,
    "proto": "tcp",
    "service": "https",
    "conn_state": "SF",
    "tactic": "Credential_Access",
    "source_release": "SIEM-Test-Injection",
}


# ---------------------------------------------------------
# SEND TESTS
# ---------------------------------------------------------

print("\nStarting SIEM rule injection tests...")
print(f"Kafka: {KAFKA_SERVER}")
print(f"Topic: {TOPIC}")

send_test_event(
    "TEST 1 - Suspicious Port Access",
    port_scan_event,
)

send_test_event(
    "TEST 2 - DNS Activity",
    dns_event,
)

send_test_event(
    "TEST 3 - High Risk Tactic",
    high_risk_event,
)

print("\n" + "=" * 60)
print("ALL TEST EVENTS SENT")
print("=" * 60)

producer.close()