"""Tests for mudgen: flow learning, MUD structure, drift check."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from make_camera_pcap import build_packets, write_pcap  # noqa: E402

from iotsentinel.mudgen import (Flow, acl_allows, build_mud,
                                drift_check, flow_str, parse_mac,
                                flows_from_packets)  # noqa: E402
from iotsentinel.pcap import read_pcap  # noqa: E402

MAC = "aa:bb:cc:dd:ee:ff"


def pcap_packets(v2=False):
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / ("camera-v2.pcap" if v2 else "camera.pcap")
    write_pcap(str(path), build_packets(v2=v2))
    return tmp, path


class TestFlowLearning(unittest.TestCase):
    def setUp(self):
        self.tmp, self.path = pcap_packets()
        self.packets = list(read_pcap(self.path))

    def tearDown(self):
        self.tmp.cleanup()

    def test_flows_learned(self):
        flows = flows_from_packets(self.packets, MAC, 2)
        kinds = {(f.direction, f.proto) for f in flows}
        self.assertIn(("out", "tcp"), kinds)      # HTTPS to cloud
        self.assertIn(("out", "udp"), kinds)      # NTP
        self.assertIn(("in", "tcp"), kinds)       # RTSP service
        https = next(f for f in flows
                     if f.direction == "out" and f.remote_port == 443)
        self.assertEqual(https.dns_name, "cloud.camera-vendor.com.")
        self.assertGreaterEqual(https.observations, 5)

    def test_min_observations_cuts_noise(self):
        flows = flows_from_packets(self.packets, MAC, 1000)
        self.assertEqual(flows, [])

    def test_non_device_traffic_ignored(self):
        flows = flows_from_packets(self.packets, "de:ad:be:ef:00:01", 2)
        self.assertEqual(flows, [])

    def test_parse_mac(self):
        self.assertEqual(parse_mac("AA-BB-CC-DD-EE-FF"),
                         "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            parse_mac("not-a-mac")


class TestMudFile(unittest.TestCase):
    def setUp(self):
        self.tmp, self.path = pcap_packets()
        self.packets = list(read_pcap(self.path))
        self.flows = flows_from_packets(self.packets, MAC, 2)
        self.mud = build_mud(MAC, self.flows, "test camera")

    def tearDown(self):
        self.tmp.cleanup()

    def test_mud_structure(self):
        m = self.mud["ietf-mud:mud"]
        for key in ("mud-version", "mud-url", "last-update",
                    "cache-validity", "is-supported", "systeminfo",
                    "from-device-policy", "to-device-policy"):
            self.assertIn(key, m)
        self.assertEqual(m["mud-version"], 1)
        self.assertIn("acl",
                      self.mud["ietf-access-control-list:acls"])
        # RFC 8520 section 9: access lists are named as objects
        fr = m["from-device-policy"]["access-lists"]["access-list"]
        to = m["to-device-policy"]["access-lists"]["access-list"]
        self.assertTrue(all("name" in a for a in fr + to))

    def test_dnsname_rule_present(self):
        aces = [ace for acl in
                self.mud["ietf-access-control-list:acls"]["acl"]
                for ace in acl["aces"]["ace"]]
        dns_rules = [a for a in aces
                     if "ietf-acldns:dst-dnsname" in a["matches"]
                     .get("ipv4", {})]
        self.assertTrue(dns_rules)
        self.assertEqual(
            dns_rules[0]["matches"]["ipv4"]["ietf-acldns:dst-dnsname"],
            "cloud.camera-vendor.com.")
        self.assertEqual(dns_rules[0]["matches"]["tcp"]
                         ["destination-port"], {"operator": "eq",
                                                "port": 443})

    def test_inbound_service_rule(self):
        m = self.mud["ietf-mud:mud"]
        self.assertEqual(
            [a["name"] for a in
             m["to-device-policy"]["access-lists"]["access-list"]],
            ["fromdev-tcp-554"])

    def test_replay_same_capture_allows_everything(self):
        """Acceptance: replaying the capture against its own policy
        yields zero candidate false-blocks."""
        drift = drift_check(self.mud, str(self.path), MAC, 2)
        self.assertEqual(drift["candidate_false_blocks"], [])
        self.assertEqual(drift["candidate_over_permissions"], [])

    def test_replay_other_capture_shows_drift(self):
        tmp2, path2 = pcap_packets(v2=True)
        try:
            drift = drift_check(self.mud, str(path2), MAC, 2)
        finally:
            tmp2.cleanup()
        self.assertEqual(drift["candidate_false_blocks"],
                         ["out tcp 198.51.100.99:443 "
                          "(telemetry.camera-vendor.com.)"])
        self.assertEqual(drift["candidate_over_permissions"],
                         ["todev-ntp"])

    def test_acl_allows_directions(self):
        cloud = Flow("out", "tcp", "198.51.100.20", 443, 41000,
                     "cloud.camera-vendor.com.")
        self.assertTrue(acl_allows(cloud, self.mud))
        inbound = Flow("in", "tcp", "192.168.1.50", 50000, 554)
        self.assertTrue(acl_allows(inbound, self.mud))
        stranger = Flow("out", "tcp", "10.9.9.9", 443, 41000,
                        "evil.example.com.")
        self.assertFalse(acl_allows(stranger, self.mud))

    def test_flow_str(self):
        f = Flow("out", "udp", "203.0.113.10", 123, 42000, "ntp.x.com.")
        self.assertEqual(flow_str(f), "out udp 203.0.113.10:123 (ntp.x.com.)")


if __name__ == "__main__":
    unittest.main()
