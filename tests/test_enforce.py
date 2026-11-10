"""Tests for enforce: rung selection and ruleset generation."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from make_camera_pcap import build_packets, write_pcap  # noqa: E402

from iotsentinel.enforce import (BLOCK_RUNG, ALLOW_RUNG, ALLOW_LOG_RUNG,
                                 RESTRICTED_RUNG, acl_rules, build_ruleset,
                                 device_tier_from_risk, pick_rung)  # noqa: E402
from iotsentinel.mudgen import build_mud, flows_from_packets  # noqa: E402
from iotsentinel.pcap import read_pcap  # noqa: E402

MAC = "aa:bb:cc:dd:ee:ff"


def make_mud():
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "camera.pcap"
    write_pcap(str(path), build_packets())
    flows = flows_from_packets(list(read_pcap(path)), MAC, 2)
    mud = build_mud(MAC, flows, "camera")
    return tmp, mud


class TestRungSelection(unittest.TestCase):
    def test_ladder(self):
        # standard + high risk -> quarantine (block rung)
        self.assertEqual(pick_rung("standard", "P1"), BLOCK_RUNG)
        self.assertEqual(pick_rung("standard", "P2"), BLOCK_RUNG)
        # safety-critical + high -> restricted, never cut off
        self.assertEqual(pick_rung("safety-critical", "P1"),
                         RESTRICTED_RUNG)
        self.assertEqual(pick_rung("safety-critical", "P2"),
                         RESTRICTED_RUNG)
        # low risk or no data -> allow rungs
        self.assertEqual(pick_rung("standard", "P3"), ALLOW_RUNG)
        self.assertEqual(pick_rung("standard", None), ALLOW_RUNG)
        self.assertEqual(pick_rung("safety-critical", "P4"),
                         ALLOW_LOG_RUNG)

    def test_bad_class(self):
        with self.assertRaises(ValueError):
            pick_rung("military", "P1")

    def test_tier_from_risk(self):
        self.assertEqual(device_tier_from_risk(
            {"findings": [{"tier": "P4"}, {"tier": "P2"}]}), "P2")
        self.assertIsNone(device_tier_from_risk({"findings": []}))
        self.assertEqual(device_tier_from_risk({"findings": [
            {"tier": "P3"}]}), "P3")


class TestRuleset(unittest.TestCase):
    def setUp(self):
        self.tmp, self.mud = make_mud()
        self.rules = acl_rules(self.mud)

    def tearDown(self):
        self.tmp.cleanup()

    def test_acl_rules_extracted(self):
        self.assertTrue(any(r["dns"] == "cloud.camera-vendor.com."
                            for r in self.rules["out"]))
        self.assertTrue(any(r["port"] == 554 and r["dir"] == "in"
                            for r in self.rules["in"]))

    def test_allow_rung_deny_by_default(self):
        txt = build_ruleset(self.mud, "standard", ALLOW_RUNG, MAC)
        self.assertIn("ether saddr " + MAC, txt)
        self.assertIn("accept", txt)
        self.assertIn("drop", txt)

    def test_safety_critical_never_blanket_drops_allowlist(self):
        """Acceptance: the restricted rung keeps the allow-list: no drop
        rule may cover an allow-listed outbound flow."""
        txt = build_ruleset(self.mud, "safety-critical",
                            RESTRICTED_RUNG, MAC)
        allow_ports = {r["port"] for r in self.rules["out"] if r["port"]}
        self.assertIn(f"limit rate", txt)     # rate-limited grants
        for line in txt.splitlines():
            stripped = line.strip()
            if stripped.endswith("drop") or "drop" in stripped.split():
                # a drop rule must not name an allow-listed port
                for p in allow_ports:
                    self.assertNotIn(f"dport {p} ", stripped)
        # inbound from non-management is dropped, allow-list kept
        self.assertIn("mgmt_v4", txt)

    def test_quarantine_allows_dns_only(self):
        txt = build_ruleset(self.mud, "standard", BLOCK_RUNG, MAC)
        self.assertIn("udp dport 53 accept", txt)
        self.assertNotIn("tcp dport 443 accept", txt)

    def test_dnsname_rules_documented_not_widened(self):
        txt = build_ruleset(self.mud, "standard", ALLOW_RUNG, MAC)
        self.assertIn("# dnsname rule: cloud.camera-vendor.com.", txt)

    def test_ruleset_is_parseable_shape(self):
        txt = build_ruleset(self.mud, "standard", ALLOW_RUNG, MAC)
        self.assertTrue(txt.startswith("#!/usr/sbin/nft -f"))
        self.assertIn("table inet iotsentinel_", txt)
        self.assertIn("chain forward {", txt)
        # braces balanced
        self.assertEqual(txt.count("{"), txt.count("}"))


if __name__ == "__main__":
    unittest.main()
