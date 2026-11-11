#!/usr/bin/env python3
"""Reproduce the sbom_firmware preprint's headline table with the tool.

Runs scan-free triage over a CycloneDX SBOM + pinned snapshot and prints
the same shape of numbers the paper reports for one image:

- findings rows, KEV rows, missing-CVSS / missing-EPSS counts (coverage)
- P1 count (S >= 0.7) under each pre-registered weighting W1/W2/W3
- rank movement W1 -> W2 and W1 -> W3

Usage:
    python reproduce/reproduce_table.py out/sbom.cdx.json \
        data/snapshots/<date>

The expected output for the bundled demo (openwrt-25.12.6 x86-64,
snapshot 2026-11-15) is checked in as expected_output.txt; run
`diff <(python reproduce/reproduce_table.py ...) expected_output.txt`
after refreshing the snapshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iotsentinel import __version__                      # noqa: E402
from iotsentinel.feeds import load_cpe_map, load_epss, load_kev, \
    load_manifest, load_nvd                              # noqa: E402
from iotsentinel.triage import (WEIGHTS, find_rows, score_row,  # noqa: E402
                                sensitivity_check, tier_of)


def main(sbom_path: str, snapshot: str) -> str:
    repo = Path(__file__).resolve().parent.parent
    cpe_map = load_cpe_map(repo / "data" / "cpe_map.json")
    nvd = load_nvd(snapshot)
    kev = load_kev(snapshot)
    epss = load_epss(snapshot)
    manifest = load_manifest(snapshot)
    sbom = Path(sbom_path)
    if sbom.is_absolute():
        sbom_obj = sbom
    else:
        sbom_obj = Path.cwd() / sbom
    sbom = sbom_obj
    data = sbom.read_text(encoding="utf-8")
    import json
    built = find_rows(json.loads(data), cpe_map, nvd, kev, epss)
    rows = built["rows"]
    not_assessed = built["not_assessed"]

    lines = []
    lines.append(f"iotsentinel {__version__} reproduction run")
    lines.append(f"sbom: {sbom.name}  snapshot: {snapshot}")
    lines.append(f"kev catalog: "
                 f"{manifest.get('feeds', {}).get('kev', {}).get('catalog_version', '?')}")
    lines.append(f"epss model: "
                 f"{manifest.get('feeds', {}).get('epss', {}).get('model_version', '?')}")
    lines.append("")
    no_cvss = sum(1 for r in rows if r["cvss"] is None)
    no_epss = sum(1 for r in rows if r["epss"] is None)
    n_kev = sum(1 for r in rows if r["kev"])
    n_components = len({c["name"] for c in json.loads(data)
                        .get("components", [])})
    lines.append(f"rows={len(rows)} components={n_components} "
                 f"not_assessed={len(not_assessed)}")
    lines.append(f"kev_rows={n_kev} no_cvss={no_cvss} no_epss={no_epss}")
    cvss_cov = round(100 * (len(rows) - no_cvss) / len(rows), 1) if rows \
        else 100.0
    epss_cov = round(100 * (len(rows) - no_epss) / len(rows), 1) if rows \
        else 100.0
    lines.append(f"coverage: cvss={cvss_cov}% epss={epss_cov}%")
    lines.append("")
    lines.append("P1 counts (S >= 0.7) per weighting:")
    for wname in ("W1", "W2", "W3"):
        w = WEIGHTS[wname]
        p1 = sum(1 for r in rows
                 if tier_of(score_row(r["cvss"], r["epss"], r["kev"], w))
                 == "P1")
        lines.append(f"  {wname} (w_cvss={w['w_cvss']}, w_epss={w['w_epss']},"
                     f" w_kev={w['w_kev']}): p1={p1}")
    sens = sensitivity_check(rows)
    lines.append("")
    lines.append(f"rank movement: {sens['moved_W1_to_W2']}/{len(rows)} "
                 f"move W1->W2, {sens['moved_W1_to_W3']}/{len(rows)} "
                 f"move W1->W3")
    if not_assessed:
        lines.append("")
        lines.append("not assessed (no CPE mapping):")
        for c in not_assessed[:10]:
            lines.append(f"  {c}")
        if len(not_assessed) > 10:
            lines.append(f"  ... and {len(not_assessed) - 10} more")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    print(main(sys.argv[1], sys.argv[2]))
