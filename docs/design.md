# iotsentinel: architecture and design notes

```
firmware rootfs ──scan──> SBOM ──triage──> ranked findings ─┐
                                                            ├──enforce──> nftables
device pcap ─────mudgen──> MUD file ────────────────────────┘
        feeds (KEV, EPSS, NVD) pinned in data/snapshots/<date>/
```

## Design rules

1. **Stdlib only at runtime.** `urllib`, `json`, `csv`, `gzip`, `tarfile`,
   `struct`, `argparse`, `ipaddress`, `unittest`. It makes the tool easy
   to audit and mirrors how the papers' own evaluation scripts work.
2. **Never invent data.** Every number the tool prints comes from a
   pinned snapshot or a file you passed. `fetch` records URLs, fetch
   timestamps, SHA-256 checksums, the KEV catalogVersion and the EPSS
   model version in `manifest.json` — the "two-date rule" in code form.
3. **State confidence, not just results.** SBOM components carry
   `evidence: package-db` or `string-match`; findings carry
   provenance flags when CVSS or EPSS is missing; unmapped components
   are listed as *not assessed*, never dropped.
4. **Never claim exploitability.** A finding is "known CVE matching this
   version range", nothing more. CPE ranges and distro backports both
   produce false positives and false negatives.

## Module map

| Module | Input | Output | Paper |
|---|---|---|---|
| `scan` | rootfs `.tar.gz` / directory | CycloneDX 1.5 SBOM | sbom_firmware |
| `feeds` | network (only here) | `data/snapshots/<date>/` + manifest | sbom_firmware |
| `triage` | SBOM + snapshot | ranked findings, P1–P4, coverage, sensitivity | sbom_firmware |
| `pcap` | classic pcap | decoded packets | mud_adoption |
| `mudgen` | pcap + device MAC | RFC 8520 MUD JSON + drift check | mud_adoption |
| `enforce` | MUD + optional triage | nftables ruleset | zt_gateway |

## Scoring (sbom_firmware, exact)

```
S = w_cvss * (CVSS / 10) + w_epss * EPSS + w_kev * KEV
P1: S >= 0.7      (the paper's decision threshold)
W1 = (0.4, 0.4, 0.2)   W2 = (0.2, 0.7, 0.1)   W3 = (0.4, 0.1, 0.5)
```

Missing CVSS / EPSS are conservative zeros with provenance flags. Below
P1, bands P2 (S >= 0.5) and P3 (S >= 0.2) exist for report readability;
the paper reports P1 counts only.

## Enforcement ladder (zt_gateway, exact)

allow → allow-and-log → restricted → block. The rung is chosen by device
class and risk tier: a high-risk standard device is quarantined (block
rung), a high-risk safety-critical device is *restricted* — allow-list
kept but rate-limited, inbound from non-management dropped, loud logs,
never a full cut-off. `enforce` generates rulesets; it does not manage a
live gateway. Test on a lab network first.

## Known limitations

See the README's *Known limitations* section. The short version:
version matching is triage, not proof; `mudgen` only knows what the
capture shows; DNS-name rules need out-of-band resolution because CDN
IPs rotate; the rulesets are drafts until `nft -c` and a lab test pass.
