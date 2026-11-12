# Changelog

All notable changes to `iotsentinel` are documented here.
Format follows Keep a Changelog; versions are SemVer.

## [0.1.0] - 2026-11-15

### Added

- `scan`: OpenWrt rootfs (opkg and apk package databases) to CycloneDX
  1.5 SBOM, with an ELF string-match fallback marked
  `evidence: string-match`.
- `fetch`: dated snapshots of CISA KEV, EPSS and per-product NVD records
  with a manifest recording URLs, timestamps and SHA-256 checksums.
- `triage`: CPE-mapped CVE lookup against the pinned snapshot, the
  sbom_firmware preprint's three-factor scoring (W1/W2/W3, P1 at 0.7),
  coverage reporting, `--sensitivity` rank-movement check, JSON and
  sortable HTML reports.
- `mudgen`: flow learning from classic pcap captures to RFC 8520 MUD
  files, with `--compare` drift detection (candidate false-blocks and
  over-permissions).
- `enforce`: MUD files compiled to nftables rulesets with the
  zt_gateway safety-aware degradation ladder.
- `reproduce/reproduce_table.py`: regenerates the paper's headline
  table (P1 counts per weighting, coverage, rank movement).
- Docker demo (`docker compose up demo`).
- 54 unit tests, GitHub Actions CI on Python 3.11/3.12.
