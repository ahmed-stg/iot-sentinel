"""scan: firmware rootfs to CycloneDX 1.5 SBOM.

Primary path (exact): OpenWrt stores installed packages either in
`usr/lib/opkg/status` (opkg, releases up to 24.x) or in `/lib/apk/db/installed`
(apk, releases 25.x onward). Both are read in memory from the tar archive;
nothing is ever extracted to disk, which also removes any path traversal
risk by construction.

Fallback path (heuristic): for binaries without package metadata, known
version strings are matched with regular expressions and reported with
`evidence: string-match` so users know the confidence.

The output is a CycloneDX 1.5 JSON SBOM. There is no dedicated purl type for
OpenWrt packages yet, so components use `pkg:generic/openwrt/<name>@<version>`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tarfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

MAX_STRING_SCAN_BYTES = 512 * 1024

# Binary version strings we can recognise without a package database.
# Each entry maps the OpenWrt package name to its version regex.
STRING_MATCHES: list[tuple[str, bytes]] = [
    (b"busybox", rb"BusyBox v(\d+\.\d+(?:\.\d+)?)"),
    (b"libopenssl", rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)"),
    (b"dnsmasq", rb"dnsmasq[-/ ](\d+\.\d+(?:\.\d+)?)"),
    (b"dropbear", rb"dropbear(?: version)? (\d{4}\.\d+)"),
    (b"hostapd", rb"hostapd v(\d+\.\d+)"),
    (b"wpad", rb"wpa_supplicant v(\d+\.\d+)"),
    (b"lighttpd", rb"lighttpd/(\d+\.\d+\.\d+)"),
    (b"libcurl", rb"curl/(\d+\.\d+\.\d+)"),
    (b"libmbedtls", rb"mbed [Tt][Ll][Ss] (\d+\.\d+\.\d+)"),
    (b"kernel", rb"Linux version (\d+\.\d+\.\d+)"),
]

BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")


@dataclass
class Component:
    name: str
    version: str            # full version as recorded by the package db
    upstream: str           # upstream version (OpenWrt revision stripped)
    evidence: str           # "package-db" or "string-match"

    def to_cdx(self) -> dict:
        return {
            "type": "application",
            "name": self.name,
            "version": self.version,
            "purl": f"pkg:generic/openwrt/{self.name}@{self.upstream}",
            "properties": [
                {"name": "iotsentinel:evidence", "value": self.evidence},
                {"name": "iotsentinel:version_upstream", "value": self.upstream},
            ],
        }


def upstream_version(version: str) -> str:
    """Strip the OpenWrt decoration suffixes so NVD/CPE matching runs on
    the upstream version: `1.36.1-3` -> `1.36.1`, and
    `6.12.112~b4125196` -> `6.12.112` (git hash decoration)."""
    version = re.sub(r"-r\d+$", "", version)
    version = re.sub(r"~[0-9a-f]{7,40}$", "", version)
    parts = version.split("-")
    if len(parts) > 1 and re.fullmatch(r"r\d+[a-z]?", parts[-1]):
        return "-".join(parts[:-1])
    if len(parts) > 1 and re.fullmatch(r"\d+", parts[-1]):
        # `1.36.1-1` style: last numeric chunk is a packaging revision
        return "-".join(parts[:-1])
    return version


def safe_member_name(name: str) -> bool:
    """Reject absolute paths and any `..` component (defense in depth:
    this tool never extracts, but it still refuses to even *read* a
    member whose name would escape an archive root)."""
    if name.startswith("/"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


def read_opkg_status(tar_path: str | os.PathLike) -> str:
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf.getmembers():
            if not safe_member_name(m.name):
                continue
            if m.name.endswith("usr/lib/opkg/status"):
                fh = tf.extractfile(m)
                if fh is not None:
                    return fh.read().decode("utf-8", "replace")
    return ""


def read_apk_installed(tar_path: str | os.PathLike) -> str:
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf.getmembers():
            if not safe_member_name(m.name):
                continue
            if m.name.endswith("lib/apk/db/installed"):
                fh = tf.extractfile(m)
                if fh is not None:
                    return fh.read().decode("utf-8", "replace")
    return ""


def parse_opkg(text: str) -> list[tuple[str, str]]:
    """opkg status: blank-line separated records with `Field: value` lines."""
    found: list[tuple[str, str]] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ": " in line:
                key, _, value = line.partition(": ")
                fields[key.strip()] = value.strip()
        if "Package" in fields and "Version" in fields:
            found.append((fields["Package"], fields["Version"]))
    return found


def parse_apk(text: str) -> list[tuple[str, str]]:
    """apk database: blank-line separated records with one-letter keys,
    `P:package`, `V:version`. Virtual `p:` provides aliases are skipped:
    they are not installed packages and would pollute the SBOM."""
    found: list[tuple[str, str]] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        pkg: str | None = None
        version: str | None = None
        for line in block.splitlines():
            if line.startswith("P:"):
                pkg = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
        if pkg and version:
            found.append((pkg, version))
    return found


def dedupe(found: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for name, version in found:
        # keep the first record; opkg lists the installed instance first
        seen.setdefault(name, version)
    return sorted(seen.items())


def string_match_members(tar_path: str | os.PathLike) -> list[tuple[str, str]]:
    """Heuristic fallback: match known version strings inside ELF
    binaries under the standard bin directories."""
    hits: dict[str, str] = {}
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf.getmembers():
            if not safe_member_name(m.name) or not m.isfile():
                continue
            if not any(m.name.startswith(d.lstrip("/")) for d in BIN_DIRS):
                continue
            if m.size > 4 * 1024 * 1024:
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            blob = fh.read(MAX_STRING_SCAN_BYTES)
            if not blob.startswith(b"\x7fELF"):
                continue
            for name, pattern in STRING_MATCHES:
                if name.decode() in hits:
                    continue
                match = re.search(pattern, blob)
                if match:
                    hits[name.decode()] = match.group(1).decode("ascii", "replace")
    return sorted(hits.items())


def scan_directory(root: str | os.PathLike) -> list[tuple[str, str]]:
    root = Path(root)
    found: list[tuple[str, str]] = []
    for rel in ("usr/lib/opkg/status", "lib/apk/db/installed"):
        p = root / rel
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            found += parse_opkg(text) if rel.endswith("opkg/status") \
                else parse_apk(text)
    if not found:
        for d in BIN_DIRS:
            bindir = root / d.lstrip("/")
            if not bindir.is_dir():
                continue
            for f in sorted(bindir.iterdir()):
                if not f.is_file() or f.stat().st_size > 4 * 1024 * 1024:
                    continue
                blob = f.read_bytes()[:MAX_STRING_SCAN_BYTES]
                if not blob.startswith(b"\x7fELF"):
                    continue
                for name, pattern in STRING_MATCHES:
                    match = re.search(pattern, blob)
                    if match:
                        found.append(
                            (name.decode(), match.group(1).decode("ascii", "replace")))
    return dedupe(found)


def build_sbom(rootfs: str | os.PathLike, source_name: str) -> dict:
    entries: list[tuple[str, str]] = []
    evidence = "package-db"
    if os.path.isdir(rootfs):
        entries = scan_directory(rootfs)
        root = Path(rootfs)
        has_db = (root / "usr/lib/opkg/status").exists() or \
            (root / "lib/apk/db/installed").exists()
        evidence = "package-db" if has_db else "string-match"
    else:
        apk_text = read_apk_installed(rootfs)
        opkg_text = read_opkg_status(rootfs)
        if apk_text.strip():
            entries = dedupe(parse_apk(apk_text))
        elif opkg_text.strip():
            entries = dedupe(parse_opkg(opkg_text))
        if not entries:
            entries = dedupe(string_match_members(rootfs))
            evidence = "string-match"

    components = [Component(name, version, upstream_version(version), evidence)
                  for name, version in entries]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z"),
            "tools": {"components": [
                {"type": "application", "name": "iotsentinel",
                 "version": __version__},
            ]},
            "component": {
                "type": "firmware",
                "name": source_name,
                "version": "",
                "properties": [
                    {"name": "iotsentinel:tool_version", "value": __version__},
                    {"name": "iotsentinel:source", "value": str(rootfs)},
                ],
            },
        },
        "components": [c.to_cdx() for c in components],
    }


def cmd_scan(args) -> int:
    rootfs = args.rootfs
    if not os.path.exists(rootfs):
        print(f"error: rootfs not found: {rootfs}", file=sys.stderr)
        return 1
    source_name = Path(rootfs).name
    try:
        sbom = build_sbom(rootfs, source_name)
    except (tarfile.TarError, OSError) as exc:
        print(f"error: cannot read rootfs: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    n = len(sbom["components"])
    ev = sbom["components"][0]["properties"][0]["value"] if n else "none"
    print(f"SBOM written to {out}: {n} components "
          f"(evidence: {ev}, sha256 {digest[:16]}...)")
    return 0
