"""Tests for scan: rootfs to CycloneDX SBOM."""

import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from iotsentinel.scan import (build_sbom, dedupe, parse_apk, parse_opkg,
                              safe_member_name, scan_directory,
                              string_match_members, upstream_version)

OPKG_TEXT = """\
Package: busybox
Version: 1.36.1-1
depends: libc
Status: install user installed

Package: libopenssl
Version: 3.0.15-r1
depends: libc

Package: dnsmasq
Version: 2.90-1
"""

APK_TEXT = """\
P:busybox
V:1.36.1-r1
o:busybox

P:libopenssl
V:3.0.15-r1
o:openssl
p:libopenssl
"""


def make_tar(path: Path, files: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, blob in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


class TestParsers(unittest.TestCase):
    def test_opkg_three_packages(self):
        self.assertEqual(parse_opkg(OPKG_TEXT),
                         [("busybox", "1.36.1-1"),
                          ("libopenssl", "3.0.15-r1"),
                          ("dnsmasq", "2.90-1")])

    def test_malformed_status_does_not_crash(self):
        self.assertEqual(parse_opkg("garbage without fields\n\n\x00\x01\n"), [])
        self.assertEqual(parse_apk("garbage\n\nP:onlyname\n"), [])

    def test_apk_records(self):
        found = parse_apk(APK_TEXT)
        self.assertIn(("busybox", "1.36.1-r1"), found)
        self.assertIn(("libopenssl", "3.0.15-r1"), found)

    def test_dedupe_keeps_first(self):
        self.assertEqual(dedupe([("a", "1"), ("a", "2"), ("b", "3")]),
                         [("a", "1"), ("b", "3")])

    def test_upstream_version(self):
        self.assertEqual(upstream_version("1.36.1-1"), "1.36.1")
        self.assertEqual(upstream_version("3.0.15-r1"), "3.0.15")
        self.assertEqual(upstream_version("2.90"), "2.90")

    def test_safe_member_name(self):
        self.assertFalse(safe_member_name("/etc/passwd"))
        self.assertFalse(safe_member_name("usr/../../etc/passwd"))
        self.assertTrue(safe_member_name("usr/bin/busybox"))


class TestScanTar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tar = Path(self.tmp.name) / "rootfs.tar.gz"
        self.busybox_elf = (b"\x7fELF" + b"\x00" * 8
                            + b"BusyBox v1.36.1 (2024-07-15)\n")
        self.dnsmasq_elf = (b"\x7fELF" + b"\x00" * 8
                            + b"dnsmasq-2.90\x00" + b"\x00" * 16)

    def tearDown(self):
        self.tmp.cleanup()

    def test_opkg_tar_three_components(self):
        make_tar(self.tar, {
            "usr/lib/opkg/status": OPKG_TEXT.encode(),
            "usr/bin/busybox": self.busybox_elf,
        })
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        comps = sbom["components"]
        self.assertEqual(len(comps), 3)
        self.assertEqual({c["name"] for c in comps},
                         {"busybox", "libopenssl", "dnsmasq"})
        self.assertEqual(comps[0]["properties"][0]["value"], "package-db")
        self.assertTrue(all(c["purl"].startswith("pkg:generic/openwrt/")
                            for c in comps))

    def test_apk_tar(self):
        make_tar(self.tar, {"lib/apk/db/installed": APK_TEXT.encode()})
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        self.assertEqual(len(sbom["components"]), 2)
        self.assertEqual(sbom["components"][0]["properties"][0]["value"],
                         "package-db")

    def test_string_match_fallback(self):
        make_tar(self.tar, {
            "bin/busybox": self.busybox_elf,
            "usr/sbin/dnsmasq": self.dnsmasq_elf,
        })
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        comps = {c["name"]: c for c in sbom["components"]}
        self.assertEqual(set(comps), {"busybox", "dnsmasq"})
        self.assertEqual(comps["busybox"]["version"], "1.36.1")
        self.assertEqual(comps["busybox"]["properties"][0]["value"],
                         "string-match")

    def test_empty_tar_yields_empty_sbom(self):
        make_tar(self.tar, {"etc/banner": b"OpenWrt\n"})
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        self.assertEqual(sbom["components"], [])

    def test_traversal_member_is_rejected(self):
        marker = Path(self.tmp.name).parent / "should_not_exist.marker"
        make_tar(self.tar, {
            "../../" + marker.name: b"evil",
            "usr/bin/busybox": self.busybox_elf,
        })
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        self.assertFalse(marker.exists())
        # the evil member must not become a component
        self.assertEqual([c["name"] for c in sbom["components"]],
                         ["busybox"])

    def test_scan_directory(self):
        root = Path(self.tmp.name) / "root"
        (root / "usr/lib/opkg").mkdir(parents=True)
        (root / "usr/lib/opkg/status").write_text(OPKG_TEXT)
        sbom = build_sbom(root, "root")
        self.assertEqual(len(sbom["components"]), 3)
        self.assertEqual(sbom["components"][0]["properties"][0]["value"],
                         "package-db")

    def test_sbom_is_valid_cyclonedx_shape(self):
        make_tar(self.tar, {"usr/lib/opkg/status": OPKG_TEXT.encode()})
        sbom = build_sbom(self.tar, "rootfs.tar.gz")
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))
        self.assertIn("metadata", sbom)
        for c in sbom["components"]:
            self.assertIn(c["type"], ("application", "library",
                                      "operating-system", "firmware"))
            self.assertIn("name", c)
            self.assertIn("version", c)


if __name__ == "__main__":
    unittest.main()
