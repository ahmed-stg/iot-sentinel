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
# 1. SBOM from an OpenWrt rootfs (fetch first: ./examples/fetch_openwrt.sh)
iotsentinel scan examples/openwrt-rootfs.tar.gz -o out/sbom.cdx.json
```

```
SBOM written to out/sbom.cdx.json: 136 components (evidence: package-db, sha256 66bf6c18b31fc711...)
```

```bash
# 2. Ranked risk using the pinned feed snapshot
iotsentinel triage out/sbom.cdx.json --snapshot data/snapshots/2026-11-15 \
    --weights W1 --sensitivity -o out/triage.json --html out/triage.html
```

```
triage: 47 findings over 136 components (assessed 6, not assessed 130)
  tiers: {'P1': 0, 'P2': 0, 'P3': 31, 'P4': 16}
  coverage: CVSS 100.0%, EPSS 100.0%
  sensitivity: 25/47 move W1->W2, 2/47 move W1->W3
  report written to out/triage.json
  html report written to out/triage.html
```

```bash
# 3. MUD file from a capture (synthetic camera capture committed in examples/)
iotsentinel mudgen examples/camera.pcap --mac aa:bb:cc:dd:ee:ff -o out/camera.mud.json
```

```
MUD file written to out/camera.mud.json: 3 outbound rules, 1 inbound rules
```

```bash
# 4. Drift: replay the same capture -> nothing blocked; replay a post-update capture
iotsentinel mudgen examples/camera.pcap --mac aa:bb:cc:dd:ee:ff \
    --compare out/camera.mud.json -o out/selfcheck.mud.json
iotsentinel mudgen examples/camera-v2.pcap --mac aa:bb:cc:dd:ee:ff \
    --compare out/camera.mud.json -o out/camera-v2.mud.json
```

```
drift vs out/camera.mud.json: 0 candidate false-blocks, 0 candidate over-permissions (of 4 observed flows)
drift vs out/camera.mud.json: 1 candidate false-blocks, 1 candidate over-permissions (of 4 observed flows)
  would block: out tcp 198.51.100.99:443 (telemetry.camera-vendor.com.)
  never exercised: todev-ntp
```

```bash
# 5. nftables rules, safety-critical device
iotsentinel enforce out/camera.mud.json --risk out/triage.json \
    --class safety-critical -o out/camera.nft
nft -c -f out/camera.nft    # syntax check only, no root needed on Linux
```

```
nftables ruleset written to out/camera.nft: class=safety-critical tier=P3 rung=allow-and-log
```

Generated ruleset (excerpt):

```nft
table inet iotsentinel_cam_aabbccddeeff {
  set cam_aabbccddeeff_allowed_v4 {
    type ipv4_addr
    elements = { 192.168.1.1/32 }
  }
  chain cam_aabbccddeeff_out {
    ct state established,related accept
    # dnsname rule: cloud.camera-vendor.com. (resolve at apply time, see README limitations)
    ip daddr @cam_aabbccddeeff_allowed_v4 udp dport 53 accept
    counter log prefix "iotsentinel-allowlog " accept
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ether saddr aa:bb:cc:dd:ee:ff jump cam_aabbccddeeff_out
    ether daddr aa:bb:cc:dd:ee:ff jump cam_aabbccddeeff_in
  }
}
```

## Commands

| Command | Input | Output |
|---|---|---|
| `fetch` | none (network) | dated snapshot of KEV, EPSS and NVD data in `data/snapshots/<date>/` |
| `scan` | rootfs `.tar.gz` or extracted directory | CycloneDX 1.5 SBOM (JSON) |
| `triage` | SBOM and snapshot | ranked findings (JSON, optional HTML), P1 to P4 tiers |
| `mudgen` | classic `.pcap` and device MAC | RFC 8520 MUD JSON |
| `enforce` | MUD file, optional triage output, device class | nftables ruleset |

Run `iotsentinel <command> --help` for all options. `fetch --resume` reuses an existing snapshot and only re-queries the NVD products that came back empty.

## How scoring works

For each CVE affecting a component, exactly as in the `sbom_firmware` preprint:

```
S = w_cvss * (CVSS / 10) + w_epss * EPSS + w_kev * KEV
tier P1 if S >= 0.7   (the paper's decision threshold; P2/P3/P4 bands below it are for readability)
```

Three pre-registered weightings are shipped: W1 base (0.4, 0.4, 0.2), W2 EPSS-heavy (0.2, 0.7, 0.1), W3 KEV-heavy (0.4, 0.1, 0.5). Missing CVSS or EPSS count as 0 with a provenance flag (the conservative rule); `--sensitivity` reports how many findings change rank position between presets, as in the paper. On the demo image, 25 of 47 findings move between W1 and W2 — the ranking is weighting-sensitive even when the P1 set is empty, which is the paper's point.

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
- `reproduce/reproduce_table.py` regenerates the preprint's headline table (per-weighting P1 counts, coverage, rank movement); its output for the bundled demo is checked in as `reproduce/expected_output.txt`:

```
rows=47 components=136 not_assessed=130
kev_rows=0 no_cvss=0 no_epss=0
coverage: cvss=100.0% epss=100.0%

P1 counts (S >= 0.7) per weighting:
  W1 (w_cvss=0.4, w_epss=0.4, w_kev=0.2): p1=0
  W2 (w_cvss=0.2, w_epss=0.7, w_kev=0.1): p1=0
  W3 (w_cvss=0.4, w_epss=0.1, w_kev=0.5): p1=0

rank movement: 25/47 move W1->W2, 2/47 move W1->W3
```

Zero P1 rows on a current release is the expected result — the paper's headline finding is that no weighting in the pre-registered family crosses the 0.7 threshold for a current OpenWrt image.

- The committed snapshot (2026-11-15, KEV catalog 2026.11.13, EPSS model v2026.06.15) is reduced to the CVEs matching the demo image's components, so the demo runs offline; run `fetch` yourself for other images.

## Known limitations (read these)

- **Version matching produces false positives and negatives.** On this very image, `triage` matches CVE-2003-0959 against kernel 6.12.112 because the NVD CPE range is written broadly. CPE and distro backports do not always agree. Treat output as triage, not proof of exploitability.
- `scan` is exact for OpenWrt (apk/opkg metadata) and heuristic for binaries without package metadata (string-based version detection, marked `evidence: string-match`).
- `mudgen` learns only what appears in the capture; incomplete captures give incomplete (too strict) policies. Classic pcap only, not pcapng.
- `enforce` generates rules; it does not manage a live gateway. DNS-name rules need out-of-band IP resolution (CDN IPs rotate) and are emitted as comments rather than silently widened. Test on a lab network first.
- The bundled pcaps are synthetic (generated by `examples/make_camera_pcap.py` from RFC 5737 addresses); they exercise the parser, they are not a field study.
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
