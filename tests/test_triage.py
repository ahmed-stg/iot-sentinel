"""Tests for triage: scoring, version matching, reporting. All offline;
uses fixture NVD/KEV/EPSS records, never the network."""

import json
import tempfile
import unittest
from pathlib import Path

from iotsentinel.triage import (WEIGHTS, P1_THRESHOLD, build_report,
                                component_cves, find_rows, score_row,
                                sensitivity_check, tier_of, version_in_range,
                                version_tuple)


def rec(cve, cvss=None, criteria=None):
    return {"id": cve, "published": "2024-01-01", "cvss": cvss,
            "criteria": criteria or [], "description": "test"}


class TestScoring(unittest.TestCase):
    def test_paper_weights(self):
        self.assertEqual(WEIGHTS["W1"], (0.4, 0.4, 0.2) and
                         {"w_cvss": 0.4, "w_epss": 0.4, "w_kev": 0.2})
        self.assertEqual(WEIGHTS["W2"]["w_epss"], 0.7)
        self.assertEqual(WEIGHTS["W3"]["w_kev"], 0.5)
        self.assertEqual(P1_THRESHOLD, 0.7)

    def test_score_matches_paper_definition(self):
        w = WEIGHTS["W1"]
        # S = 0.4*(cvss/10) + 0.4*epss + 0.2*kev
        self.assertAlmostEqual(score_row(9.8, 0.5, False, w),
                               0.4 * 0.98 + 0.4 * 0.5)
        self.assertAlmostEqual(score_row(9.8, 0.5, True, w),
                               0.4 * 0.98 + 0.4 * 0.5 + 0.2)

    def test_missing_cvss_and_epss_conservative(self):
        w = WEIGHTS["W1"]
        self.assertAlmostEqual(score_row(None, 0.5, False, w), 0.2)
        self.assertAlmostEqual(score_row(9.8, None, False, w), 0.392)

    def test_tier_bands(self):
        self.assertEqual(tier_of(0.7), "P1")
        self.assertEqual(tier_of(0.5), "P2")
        self.assertEqual(tier_of(0.2), "P3")
        self.assertEqual(tier_of(0.19), "P4")

    def test_kev_row_reaches_p1_with_enough_signal(self):
        # paper semantics: KEV contributes w_kev but P1 still needs the
        # 0.7 threshold to be crossed by the combined score
        w = WEIGHTS["W1"]
        self.assertEqual(tier_of(score_row(9.8, 0.5, True, w)), "P1")

    def test_kev_alone_does_not_auto_p1(self):
        # a KEV hit with no CVSS/EPSS data stays below the 0.7 threshold
        # under W1 (0.4, 0.4, 0.2) - this matches the paper's finding
        self.assertEqual(tier_of(score_row(None, None, True,
                                           WEIGHTS["W1"])), "P3")

    def test_version_tuple(self):
        self.assertGreater(version_tuple("1.36.2"), version_tuple("1.36.1"))
        self.assertLess(version_tuple("2.90"), version_tuple("2.91"))
        self.assertEqual(version_tuple("3.0.15"), version_tuple("3.0.15"))


class TestVersionMatching(unittest.TestCase):
    def test_range_including(self):
        crit = {"cpe": "cpe:2.3:a:busybox:busybox:1.0:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.30",
                "versionEndExcluding": "1.37"}
        self.assertTrue(version_in_range("1.36.1", crit))
        self.assertFalse(version_in_range("1.37.0", crit))

    def test_end_including(self):
        crit = {"cpe": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*",
                "versionEndIncluding": "2.90"}
        self.assertTrue(version_in_range("2.90", crit))
        self.assertFalse(version_in_range("2.91", crit))

    def test_component_cves_filters_by_version(self):
        nvd = {"busybox:busybox": {"records": [
            rec("CVE-2024-0001", 7.5, [
                {"cpe": "cpe:2.3:a:busybox:busybox:1.36.0:*:*:*:*:*:*:*"}]),
            rec("CVE-2024-0002", 5.0, []),
        ]}}
        hits = component_cves("busybox", "1.36.1", "busybox", "busybox", nvd)
        # exact-version criterion 1.36.0 != 1.36.1, record without criteria kept
        self.assertEqual([r["id"] for r in hits], ["CVE-2024-0002"])


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.snap = Path(self.tmp.name) / "2026-11-15"
        (self.snap / "nvd").mkdir(parents=True)
        self.sbom = Path(self.tmp.name) / "sbom.json"
        self.sbom.write_text(json.dumps({
            "components": [
                {"name": "busybox", "version": "1.36.1",
                 "properties": [{"name": "iotsentinel:version_upstream",
                                 "value": "1.36.1"}]},
                {"name": "mystery-pkg", "version": "9.9"},
            ]}))
        (self.snap / "nvd" / "busybox__busybox.json").write_text(json.dumps(
            {"records": [rec("CVE-2024-0003", 9.8)]}))
        (self.snap / "kev.json").write_text(json.dumps({
            "catalogVersion": "test-1", "vulnerabilities": [
                {"cveID": "CVE-2024-0003"}]}))
        (self.snap / "epss.csv").write_text("cve,epss,percentile\n"
                                            "CVE-2024-0003,0.5,0.9\n")
        (self.snap / "manifest.json").write_text(json.dumps({
            "feeds": {"kev": {"catalog_version": "test-1"},
                      "epss": {"model_version": "EPSS v3"}}}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_find_rows_and_not_assessed(self):
        nvd = {"busybox:busybox": {"records": [rec("CVE-2024-0003", 9.8)]}}
        kev = {"CVE-2024-0003": {}}
        built = find_rows({"components": [
            {"name": "busybox", "version": "1.36.1",
             "properties": [{"name": "iotsentinel:version_upstream",
                             "value": "1.36.1"}]},
            {"name": "mystery", "version": "1.0"}]},
            {"busybox": "busybox:busybox"}, nvd, kev,
            {"CVE-2024-0003": 0.5})
        self.assertEqual(len(built["rows"]), 1)
        self.assertEqual(built["not_assessed"], ["mystery@1.0"])
        self.assertTrue(built["rows"][0]["kev"])

    def test_missing_epss_handled(self):
        nvd = {"busybox:busybox": {"records": [rec("CVE-2024-0003", 9.8)]}}
        built = find_rows({"components": [
            {"name": "busybox", "version": "1.36.1",
             "properties": [{"name": "iotsentinel:version_upstream",
                             "value": "1.36.1"}]}]},
            {"busybox": "busybox:busybox"}, nvd, {}, {})
        self.assertTrue(built["rows"][0]["no_epss"])
        w = WEIGHTS["W1"]
        self.assertAlmostEqual(score_row(9.8, None, False, w), 0.392)

    def test_report_p1_and_coverage(self):
        nvd = {"busybox:busybox": {"records": [rec("CVE-2024-0003", 9.8)]}}
        kev = {"CVE-2024-0003": {}}
        built = find_rows({"components": [
            {"name": "busybox", "version": "1.36.1",
             "properties": [{"name": "iotsentinel:version_upstream",
                             "value": "1.36.1"}]}]},
            {"busybox": "busybox:busybox"}, nvd, kev,
            {"CVE-2024-0003": 0.5})
        rep = build_report(str(self.sbom), str(self.snap), built["rows"],
                           built["not_assessed"], "W1",
                           {"feeds": {"kev": {"catalog_version": "test-1"},
                                      "epss": {"model_version": "EPSS v3"}}})
        self.assertEqual(rep["counts"]["tiers"]["P1"], 1)
        self.assertEqual(rep["coverage"]["cvss_pct"], 100.0)
        self.assertEqual(rep["coverage"]["epss_pct"], 100.0)
        self.assertEqual(rep["kev_catalog_version"], "test-1")
        self.assertEqual(rep["epss_model_version"], "EPSS v3")

    def test_sensitivity_identical_presets_zero_moves(self):
        rows = [{"cve": "CVE-1", "component": "a", "version": "1",
                 "cvss": 5.0, "epss": 0.3, "kev": False},
                {"cve": "CVE-2", "component": "a", "version": "1",
                 "cvss": 3.0, "epss": 0.1, "kev": False}]
        # identical rows under all weightings -> no movement
        rows2 = [dict(r) for r in rows]
        sens = sensitivity_check(rows2)
        self.assertEqual(sens["moved_W1_to_W2"], 0)
        self.assertEqual(sens["moved_W1_to_W3"], 0)


if __name__ == "__main__":
    unittest.main()
