"""Tests for feeds: offline parsing and loading only (no network)."""

import json
import tempfile
import unittest
from pathlib import Path

from iotsentinel.feeds import (load_cpe_map, load_epss, load_kev,
                               load_manifest, load_nvd, parse_cpe_spec,
                               sha256_bytes, trim_nvd_item)


class TestCpeMap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = Path(self.tmp.name) / "cpe_map.json"
        p.write_text(json.dumps({
            "_comment": "ignore",
            "busybox": "busybox:busybox",
            "kernel": "o:linux:linux_kernel",
        }))
        self.map = load_cpe_map(p)

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_to_part_a(self):
        self.assertEqual(self.map["busybox"], "a:busybox:busybox")

    def test_part_prefix_kept(self):
        self.assertEqual(self.map["kernel"], "o:linux:linux_kernel")

    def test_comment_skipped(self):
        self.assertNotIn("_comment", self.map)

    def test_parse_cpe_spec(self):
        self.assertEqual(parse_cpe_spec("a:arm:mbed_tls"),
                         ("a", "arm", "mbed_tls"))
        self.assertEqual(parse_cpe_spec("o:linux:linux_kernel"),
                         ("o", "linux", "linux_kernel"))
        with self.assertRaises(ValueError):
            parse_cpe_spec("x:y:z")


class TestSnapshotLoading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        snap = Path(self.tmp.name)
        (snap / "kev.json").write_text(json.dumps({
            "catalogVersion": "kev-test",
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "product": "X"}]}))
        (snap / "epss.csv").write_text(
            "# model:EPSS v3\n"
            "cve,epss,percentile\n"
            "CVE-2024-0001,0.42,0.9\n"
            "CVE-2024-0002,0.01,0.1\n")
        (snap / "nvd").mkdir()
        (snap / "nvd" / "busybox__busybox.json").write_text(json.dumps({
            "query": "cpe:2.3:a:busybox:busybox",
            "total_results": 2,
            "records": [
                trim_nvd_item({
                    "id": "CVE-2024-0003",
                    "descriptions": [{"lang": "en", "value": "d"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {
                        "baseScore": 7.8}}]},
                    "configurations": [{"nodes": [{"operator": "OR",
                        "cpeMatch": [{"vulnerable": True,
                            "criteria": "cpe:2.3:a:busybox:busybox:1.35:"
                                        "*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.30",
                            "versionEndExcluding": "1.36"}]}]}],
                })]}))
        (snap / "manifest.json").write_text(json.dumps({
            "tool_version": "test", "feeds": {}}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_kev(self):
        kev = load_kev(self.tmp.name)
        self.assertIn("CVE-2024-0001", kev)

    def test_load_epss(self):
        epss = load_epss(self.tmp.name)
        self.assertAlmostEqual(epss["CVE-2024-0001"], 0.42)

    def test_load_nvd_reduced_form(self):
        nvd = load_nvd(self.tmp.name)
        self.assertIn("busybox:busybox", nvd)
        recs = nvd["busybox:busybox"]["records"]
        self.assertEqual(recs[0]["id"], "CVE-2024-0003")
        self.assertAlmostEqual(recs[0]["cvss"], 7.8)
        self.assertTrue(recs[0]["criteria"][0]["versionEndExcluding"],
                        "1.36")

    def test_load_manifest(self):
        m = load_manifest(self.tmp.name)
        self.assertEqual(m["tool_version"], "test")

    def test_missing_snapshot_loads_empty(self):
        self.assertEqual(load_kev("/nonexistent"), {})
        self.assertEqual(load_epss("/nonexistent"), {})
        self.assertEqual(load_nvd("/nonexistent"), {})

    def test_sha256(self):
        self.assertEqual(sha256_bytes(b"abc"),
                         "ba7816bf8f01cfea414140de5dae2223"
                         "b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()
