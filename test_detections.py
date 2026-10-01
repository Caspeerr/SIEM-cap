import json
import math
import unittest

from rules import detections
from rules.engine import RULES
from storage import json_safe_value


def make_event(**overrides):
    event = {
        "ts": 1_800_000_000.0,
        "uid": None,
        "src_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "src_port": 40000,
        "dest_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "conn_state": "SF",
        "orig_bytes": 1024,
        "resp_bytes": 1024,
        "duration": 1.0,
    }
    event.update(overrides)
    return event


class DetectionRulesTests(unittest.TestCase):
    def setUp(self):
        detections.reset_detection_state()

    def test_engine_registers_eight_rules(self):
        self.assertEqual(len(RULES), 8)

    def test_stream_json_converts_non_finite_values_to_null(self):
        cleaned = json_safe_value({"value": math.nan, "nested": [math.inf, 1]})
        self.assertEqual(json.loads(json.dumps(cleaned, allow_nan=False)), {
            "value": None,
            "nested": [None, 1],
        })

    def test_brute_force_requires_repeated_rejections(self):
        for attempt in range(detections.BRUTE_FORCE_THRESHOLD - 1):
            event = make_event(ts=1_800_000_000.0 + attempt, dest_port=22, conn_state="REJ")
            self.assertIsNone(detections.rule_brute_force(event))

        event = make_event(ts=1_800_000_010.0, dest_port=22, conn_state="REJ")
        self.assertEqual(detections.rule_brute_force(event)["rule_id"], "BRUTE_FORCE_001")

    def test_port_scan_requires_distinct_ports(self):
        result = None
        for port in range(1, detections.PORT_SCAN_THRESHOLD + 1):
            result = detections.rule_port_scan(make_event(dest_port=port))

        self.assertEqual(result["rule_id"], "PORT_SCAN_001")

    def test_large_transfer_requires_internal_to_external_flow(self):
        event = make_event(dest_ip="8.8.8.8", orig_bytes=detections.LARGE_TRANSFER_BYTES)
        self.assertEqual(detections.rule_large_outbound_transfer(event)["rule_id"], "EXFIL_001")

        event["dest_ip"] = "10.0.0.1"
        self.assertIsNone(detections.rule_large_outbound_transfer(event))

        event.update(dest_ip="8.8.8.8", orig_bytes=float("nan"))
        self.assertIsNone(detections.rule_large_outbound_transfer(event))

    def test_dns_burst_requires_dns_traffic(self):
        result = None
        for second in range(detections.DNS_BURST_THRESHOLD):
            event = make_event(ts=1_800_000_000.0 + second, dest_port=53, service="dns")
            result = detections.rule_dns_burst(event)

        self.assertEqual(result["rule_id"], "DNS_BURST_001")

    def test_rare_destination_port_after_baseline(self):
        for second in range(detections.PORT_BASELINE_EVENTS):
            detections.rule_unusual_destination_port(make_event(ts=1_800_000_000.0 + second))

        alert = detections.rule_unusual_destination_port(
            make_event(ts=1_800_000_200.0, dest_ip="8.8.8.8", dest_port=9001)
        )
        self.assertEqual(alert["rule_id"], "UNUSUAL_PORT_001")

        self.assertIsNone(
            detections.rule_unusual_destination_port(
                make_event(ts=1_800_000_201.0, proto="icmp", dest_port=3)
            )
        )
        self.assertIsNone(
            detections.rule_unusual_destination_port(
                make_event(ts=1_800_000_202.0, proto="udp", dest_port=5353)
            )
        )

    def test_long_lived_connection_threshold(self):
        event = make_event(duration=detections.LONG_CONNECTION_SECONDS)
        self.assertEqual(detections.rule_long_connection(event)["rule_id"], "LONG_CONNECTION_001")

    def test_connection_flood_threshold_is_time_bounded(self):
        result = None
        for second in range(detections.CONNECTION_RATE_THRESHOLD):
            event = make_event(ts=1_800_000_000.0 + second / detections.CONNECTION_RATE_THRESHOLD)
            result = detections.rule_connection_flood(event)

        self.assertEqual(result["rule_id"], "CONNECTION_FLOOD_001")

    def test_regular_repeated_destination_is_beacon_candidate(self):
        result = None
        for index in range(detections.BEACON_MIN_CONNECTIONS):
            event = make_event(ts=1_800_000_000.0 + index * 60)
            result = detections.rule_periodic_beacon(event)

        self.assertEqual(result["rule_id"], "PERIODIC_BEACON_001")


if __name__ == "__main__":
    unittest.main()