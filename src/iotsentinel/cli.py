"""Command line interface for iotsentinel.

One argparse parser with subcommands fetch, scan, triage, mudgen and
enforce, each dispatching to a function in its module. Every command
prints only what it computed; nothing is fetched from the network
except by the explicit `fetch` command.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iotsentinel",
        description="Firmware image to ranked risk to enforced network policy.",
    )
    parser.add_argument("--version", action="version",
                        version=f"iotsentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser(
        "fetch",
        help="download a dated snapshot of KEV, EPSS and NVD data",
        description="Download CISA KEV, the EPSS daily score file and the "
                    "NVD records for the configured CPE map into "
                    "data/snapshots/<date>/, with a manifest recording "
                    "URLs, timestamps and SHA-256 checksums.")
    p_fetch.add_argument("--snapshots-dir", default="data/snapshots",
                         help="base directory for dated snapshots")
    p_fetch.add_argument("--date", default=None,
                         help="snapshot date (default: today, UTC)")
    p_fetch.add_argument("--nvd-sleep", type=float, default=7.0,
                         help="seconds between NVD API calls (rate limit)")
    p_fetch.add_argument("--sbom", default=None,
                         help="optional CycloneDX SBOM: when given, NVD "
                              "records are reduced to the CVEs matching "
                              "its components (keeps the snapshot small "
                              "enough to commit)")
    p_fetch.add_argument("--resume", action="store_true",
                         help="reuse an existing snapshot: keep already-"
                              "downloaded KEV/EPSS files and NVD records "
                              "instead of re-downloading, and only query "
                              "the NVD products that came back empty "
                              "(useful after 503s; NVD is rate limited)")

    p_scan = sub.add_parser(
        "scan",
        help="build a CycloneDX 1.5 SBOM from a firmware rootfs",
        description="Read an OpenWrt rootfs tar.gz (or an extracted "
                    "directory), list installed packages from the package "
                    "database (opkg or apk), fall back to string matching "
                    "for binaries without metadata, and emit a CycloneDX "
                    "1.5 JSON SBOM.")
    p_scan.add_argument("rootfs", help="rootfs .tar.gz or extracted directory")
    p_scan.add_argument("-o", "--out", required=True,
                        help="output SBOM path (JSON)")

    p_triage = sub.add_parser(
        "triage",
        help="map an SBOM to CVEs and rank them",
        description="Map SBOM components to CVEs using the pinned snapshot "
                    "and the CPE map, score every finding "
                    "S = w_cvss*(CVSS/10) + w_epss*EPSS + w_kev*KEV under "
                    "the pre-registered weightings from the paper, assign "
                    "P1-P4 tiers and report coverage. Never touches the "
                    "network: pass --snapshot.")
    p_triage.add_argument("sbom", help="CycloneDX SBOM from `scan`")
    p_triage.add_argument("--snapshot", required=True,
                          help="snapshot directory from `fetch`")
    p_triage.add_argument("--weights", default="W1",
                          choices=["W1", "W2", "W3"],
                          help="weighting preset (default: W1)")
    p_triage.add_argument("--sensitivity", action="store_true",
                          help="report how many findings change rank "
                               "between the weightings")
    p_triage.add_argument("-o", "--out", required=True,
                          help="output report path (JSON)")
    p_triage.add_argument("--html", default=None,
                          help="optional HTML report path")

    p_mudgen = sub.add_parser(
        "mudgen",
        help="learn a RFC 8520 MUD file from a traffic capture",
        description="Read a classic libpcap capture of one device, learn "
                    "its observed flows (direction, protocol, remote "
                    "endpoint, DNS names) and emit a RFC 8520 MUD "
                    "definition as JSON.")
    p_mudgen.add_argument("pcap", help="classic .pcap capture")
    p_mudgen.add_argument("--mac", required=True,
                          help="device MAC address to model")
    p_mudgen.add_argument("--min-observations", type=int, default=2,
                          help="minimum observations before a flow becomes "
                               "a rule (noise cut, default: 2)")
    p_mudgen.add_argument("--compare", default=None, metavar="OLD_MUD",
                          help="drift check: report flows the old policy "
                               "would block or never exercised")
    p_mudgen.add_argument("-o", "--out", required=True,
                          help="output MUD file path (JSON)")

    p_enforce = sub.add_parser(
        "enforce",
        help="compile a MUD file into an nftables ruleset",
        description="Compile a MUD file into an nftables ruleset for a "
                    "gateway, with the safety-aware degradation ladder "
                    "from the zt_gateway paper: allow, allow-and-log, "
                    "restricted, and block, where safety-critical devices "
                    "are restricted, never cut off.")
    p_enforce.add_argument("mud", help="MUD file from `mudgen`")
    p_enforce.add_argument("--risk", default=None,
                           help="triage report from `triage` to pick the "
                                "ladder rung from the device risk tier")
    p_enforce.add_argument("--class", dest="device_class", default="standard",
                           choices=["standard", "safety-critical"],
                           help="device class (default: standard)")
    p_enforce.add_argument("--table", default="iotsentinel",
                           help="nftables table name")
    p_enforce.add_argument("-o", "--out", required=True,
                           help="output ruleset path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "fetch":
        from .feeds import cmd_fetch
        return cmd_fetch(args)
    if args.command == "scan":
        from .scan import cmd_scan
        return cmd_scan(args)
    if args.command == "triage":
        from .triage import cmd_triage
        return cmd_triage(args)
    if args.command == "mudgen":
        from .mudgen import cmd_mudgen
        return cmd_mudgen(args)
    if args.command == "enforce":
        from .enforce import cmd_enforce
        return cmd_enforce(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
