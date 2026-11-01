# iotsentinel

From firmware image to ranked risk to enforced network policy, in one small, auditable, stdlib-only Python tool.

![python](https://img.shields.io/badge/python-3.11%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)

`iotsentinel` takes an embedded Linux firmware image, builds an SBOM, ranks the known vulnerabilities in it with a multi-factor score (CVSS x EPSS x CISA KEV), and then generates a least-privilege network policy (RFC 8520 MUD file plus nftables rules) for the device, with a safety-aware mode that restricts instead of blocking devices that must stay up.

It is the practical companion of my research preprints:

| Module | What it does | Research behind it |
|---|---|---|
| `scan` | Firmware rootfs to CycloneDX SBOM | `sbom_firmware/` (Theme 1) |
| `triage` | CVE mapping and CVSS x EPSS x KEV ranking, with weighting sensitivity check | `sbom_firmware/` (Theme 1) |
| `mudgen` | pcap to RFC 8520 MUD file, with allow-list drift detection | `mud_adoption/` (Theme 4) |
| `enforce` | MUD/policy to nftables, with safety-aware degradation | `zt_gateway/` (Theme 5) |

<!-- TODO: add links to the preprints (arXiv/Zenodo/GitHub PDFs) here -->

## Why this exists

Papers describe methods; this repo lets you run them. Every number the tool prints can be reproduced from pinned data snapshots (see [Reproducibility](#reproducibility)).

## Install

```bash
git clone https://github.com/<you>/iotsentinel.git
cd iotsentinel
python3 -m venv .venv && source .venv/bin/activate   # optional, there are no runtime deps
pip install -e .                                      # exposes the `iotsentinel` command
```

Requires Python 3.11+. Optional: `nftables` (to syntax-check rules with `nft -c`), `tcpdump` (to capture traffic), Docker (for the demo).

## Quickstart (offline, uses the bundled snapshot)

```bash
# 1. SBOM from an OpenWrt rootfs
iotsentinel scan examples/openwrt-rootfs.tar.gz -o out/sbom.cdx.json

# 2. Ranked risk using the pinned feed snapshot
iotsentinel triage out/sbom.cdx.json --snapshot data/snapshots/2026-11-12 \
    --weights balanced -o out/triage.json --html out/triage.html

# 3. Do the rankings survive a change of weights?
iotsentinel triage out/sbom.cdx.json --snapshot data/snapshots/2026-11-12 --sensitivity

# 4. MUD file from a capture
iotsentinel mudgen examples/camera.pcap --mac aa:bb:cc:dd:ee:ff -o out/camera.mud.json

# 5. nftables rules, safety-critical device is restricted, not cut off
iotsentinel enforce out/camera.mud.json --risk out/triage.json --class safety-critical -o out/camera.nft
nft -c -f out/camera.nft    # syntax check only, no root needed on Linux
```

> **Placeholder:** paste your real terminal output here once the tool runs. Do not publish invented numbers.

## Commands

| Command | Input | Output |
|---|---|---|
| `fetch` | none (network) | dated snapshot of KEV, EPSS and NVD data in `data/snapshots/<date>/` |
| `scan` | rootfs `.tar.gz` or extracted directory | CycloneDX 1.5 SBOM (JSON) |
| `triage` | SBOM and snapshot | ranked findings (JSON, optional HTML), P1 to P4 tiers |
| `mudgen` | classic `.pcap` and device MAC | RFC 8520 MUD JSON |
| `enforce` | MUD file, optional triage output, device class | nftables ruleset |

Run `iotsentinel <command> --help` for all options.

## How scoring works

For each CVE affecting a component:

```
score = w_cvss * (CVSS / 10) + w_epss * EPSS      # then KEV overrides the tier
tier  = P1 if in CISA KEV, otherwise banded by score (P2, P3, P4)
```

Three weight presets (`balanced`, `exploit-heavy`, `severity-heavy`) are shipped, and `--sensitivity` reports how many findings change rank between presets, as in the paper.

## Architecture

```
firmware rootfs ──scan──> SBOM ──triage──> ranked findings ─┐
                                                            ├──enforce──> nftables
device pcap ─────mudgen──> MUD file ────────────────────────┘
        feeds (KEV, EPSS, NVD) pinned in data/snapshots/<date>/
```

## Reproducibility

- Feeds are stored as dated snapshots; `triage` never touches the network unless you run `fetch`.
- Each report records the snapshot date, EPSS model version and tool version.
- `reproduce/` regenerates one table from the preprint using the tool (see `reproduce/README.md`).

## Known limitations (read these)

- **Version matching produces false positives and negatives.** CPE and distro backports do not always agree. Treat output as triage, not proof of exploitability.
- `scan` is exact for OpenWrt (opkg metadata) and heuristic for binaries without package metadata (string-based version detection).
- `mudgen` learns only what appears in the capture; incomplete captures give incomplete (too strict) policies.
- `enforce` generates rules; it does not manage a live gateway. Test on a lab network first.
- Not a substitute for a professional audit.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Security

See [SECURITY.md](SECURITY.md) for how to report issues.

## License

MIT. See [LICENSE](LICENSE).

## Author

Ahmed Kaouadji, ESI Sidi Bel Abbes. Preprints: <!-- TODO: link -->
