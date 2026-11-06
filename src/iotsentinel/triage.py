"""triage: SBOM to CVE mapping, multi-factor scoring and ranking.

Mapping is deliberately honest and simple: `data/cpe_map.json` maps
popular package names to NVD CPE vendor:product pairs; components with no
entry are reported as "not assessed" and are never silently dropped.

Scoring follows the `sbom_firmware` preprint exactly:

    S = w_cvss * (CVSS / 10) + w_epss * EPSS + w_kev * KEV

with the three pre-registered weightings

    W1 (base)        = (0.4, 0.4, 0.2)
    W2 (EPSS-heavy)  = (0.2, 0.7, 0.1)
    W3 (KEV-heavy)   = (0.4, 0.1, 0.5)

P1 is S >= 0.7 (the paper's decision threshold); P2/P3/P4 bands below it
(S >= 0.5 / S >= 0.2 / otherwise) exist so a report stays readable; the
paper only reports P1 counts. Missing CVSS and missing EPSS are treated
as 0 with provenance flags (the paper's conservative rule), and coverage
percentages are reported instead of being hidden.

The `--sensitivity` check re-ranks all findings under each weighting and
counts how many change rank position between W1 and W2 / W3, as in the
paper.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from string import Template

from . import __version__
from .feeds import load_epss, load_kev, load_manifest, load_nvd

WEIGHTS = {
    "W1": {"w_cvss": 0.4, "w_epss": 0.4, "w_kev": 0.2},
    "W2": {"w_cvss": 0.2, "w_epss": 0.7, "w_kev": 0.1},
    "W3": {"w_cvss": 0.4, "w_epss": 0.1, "w_kev": 0.5},
}
P1_THRESHOLD = 0.7
P2_THRESHOLD = 0.5
P3_THRESHOLD = 0.2

TIER_ORDER = ["P1", "P2", "P3", "P4"]


def version_tuple(version: str) -> tuple:
    """Comparable tuple: ('1.36.1a') -> ((1,''),(36,''),(1,'a'))."""
    parts = []
    for chunk in version.split("."):
        m = ""
        while chunk and chunk[-1].isalpha():
            m = chunk[-1] + m
            chunk = chunk[:-1]
        try:
            parts.append((int(chunk), m))
        except ValueError:
            digits = "".join(c for c in chunk if c.isdigit()) or "0"
            parts.append((int(digits), m))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    ta, tb = version_tuple(a), version_tuple(b)
    for pa, pb in zip(ta, tb):
        if pa != pb:
            return -1 if pa < pb else 1
    if len(ta) != len(tb):
        return -1 if len(ta) < len(tb) else 1
    return 0


def version_in_range(version: str, crit: dict) -> bool:
    """True if `version` satisfies one CPE match's version constraints."""
    if all(f not in crit for f in ("versionStartIncluding",
                                   "versionStartExcluding",
                                   "versionEndIncluding",
                                   "versionEndExcluding")):
        return True
    lo_ok = True
    hi_ok = True
    if "versionStartIncluding" in crit:
        lo_ok = _cmp(version, crit["versionStartIncluding"]) >= 0
    elif "versionStartExcluding" in crit:
        lo_ok = _cmp(version, crit["versionStartExcluding"]) > 0
    if "versionEndIncluding" in crit:
        hi_ok = _cmp(version, crit["versionEndIncluding"]) <= 0
    elif "versionEndExcluding" in crit:
        hi_ok = _cmp(version, crit["versionEndExcluding"]) < 0
    return lo_ok and hi_ok


def cpe_product_version(cpe: str) -> str | None:
    """The version field of a 2.3 CPE string, or None for wildcards."""
    fields = cpe.split(":")
    if len(fields) < 6:
        return None
    return None if fields[5] == "*" else fields[5]


def cpe_matches(criteria: dict, vendor: str, product: str,
                version: str) -> bool:
    cpe = criteria.get("cpe", "")
    fields = cpe.split(":")
    if len(fields) < 6:
        return False
    if fields[2] != "a" or fields[3] != vendor or fields[4] != product:
        return False
    cver = cpe_product_version(cpe)
    if cver is not None and _cmp(version, cver) != 0:
        # exact-version criteria: also accept packaging-decorated forms
        if not version.startswith(cver):
            return False
    return version_in_range(version, criteria)


def component_cves(component: str, upstream: str, vendor: str, product: str,
                   nvd: dict[str, dict]) -> list[dict]:
    """CVE records for a component version, from the pinned snapshot."""
    records = nvd.get(f"{vendor}:{product}", {}).get("records", [])
    hits = []
    for rec in records:
        if rec.get("criteria"):
            matched = any(cpe_matches(c, vendor, product, upstream)
                          for c in rec["criteria"])
        else:
            matched = True  # record without criteria: keep, flagged
        if matched:
            hits.append(rec)
    return hits


def score_row(cvss: float | None, epss: float | None, kev: bool,
              weights: dict) -> float:
    w = weights
    return (w["w_cvss"] * ((cvss / 10.0) if cvss is not None else 0.0)
            + w["w_epss"] * (epss if epss is not None else 0.0)
            + w["w_kev"] * (1.0 if kev else 0.0))


def tier_of(score: float) -> str:
    if score >= P1_THRESHOLD:
        return "P1"
    if score >= P2_THRESHOLD:
        return "P2"
    if score >= P3_THRESHOLD:
        return "P3"
    return "P4"


def find_rows(sbom: dict, cpe_map: dict[str, str], nvd: dict[str, dict],
              kev: dict[str, dict], epss: dict[str, float]) -> dict:
    """Build one finding row per (component, CVE). Returns rows plus the
    not-assessed component list."""
    rows: list[dict] = []
    not_assessed: list[str] = []
    for comp in sbom.get("components", []):
        name = comp["name"]
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        upstream = props.get("iotsentinel:version_upstream", comp["version"])
        mapping = cpe_map.get(name)
        if mapping is None or ":" not in mapping:
            not_assessed.append(f"{name}@{upstream}")
            continue
        vendor, product = mapping.split(":", 1)
        for rec in component_cves(name, upstream, vendor, product, nvd):
            cve_id = rec["id"]
            cvss = rec.get("cvss")
            epss_val = epss.get(cve_id)
            rows.append({
                "cve": cve_id,
                "component": name,
                "version": upstream,
                "cvss": cvss,
                "epss": epss_val,
                "kev": cve_id in kev,
                "published": rec.get("published", ""),
                "description": rec.get("description", ""),
                "no_cvss": cvss is None,
                "no_epss": epss_val is None,
            })
    # dedupe (same CVE can appear twice for aliased packages)
    seen: set[tuple[str, str]] = set()
    unique = []
    for r in rows:
        key = (r["cve"], r["component"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return {"rows": unique, "not_assessed": sorted(set(not_assessed))}


def rank_key(row: dict, weights: dict) -> tuple:
    # score desc, then CVE id asc for a deterministic total order
    return (-score_row(row.get("cvss"), row.get("epss"), row.get("kev", False),
                       weights),
            row.get("cve", ""))


def sensitivity_check(rows: list[dict]) -> dict:
    """How many findings change rank position between weightings."""
    out: dict[str, dict] = {}
    base_ranks: dict[str, int] | None = None
    for wname in ("W1", "W2", "W3"):
        ordered = sorted(rows, key=lambda r: rank_key(r, WEIGHTS[wname]))
        pos = {r["cve"] + "@" + r["component"]: i
               for i, r in enumerate(ordered)}
        out[wname] = pos
        if wname == "W1":
            base_ranks = pos
    moved_w2 = sum(1 for k, p in out["W2"].items()
                   if base_ranks and base_ranks.get(k) != p)
    moved_w3 = sum(1 for k, p in out["W3"].items()
                   if base_ranks and base_ranks.get(k) != p)
    return {"n_findings": len(rows),
            "moved_W1_to_W2": moved_w2,
            "moved_W1_to_W3": moved_w3}


def build_report(sbom_path: str, snapshot: str, rows: list[dict],
                 not_assessed: list[str], weights_name: str,
                 manifest: dict) -> dict:
    weights = WEIGHTS[weights_name]
    scored = []
    for r in rows:
        s = score_row(r["cvss"], r["epss"], r["kev"], weights)
        q = dict(r)
        q["score"] = round(s, 4)
        q["tier"] = tier_of(s)
        q["weights"] = weights_name
        scored.append(q)
    scored.sort(key=lambda r: rank_key(r, weights))
    n = len(scored)
    with_cvss = sum(1 for r in scored if r["cvss"] is not None)
    with_epss = sum(1 for r in scored if r["epss"] is not None)
    tiers = {t: sum(1 for r in scored if r["tier"] == t)
             for t in TIER_ORDER}
    kev_rows = sum(1 for r in scored if r["kev"])
    components = {c["name"] for c in
                  json.loads(Path(sbom_path).read_text(encoding="utf-8"))
                  .get("components", [])}
    kev_catalog = manifest.get("feeds", {}).get("kev", {}).get(
        "catalog_version", "")
    epss_model = manifest.get("feeds", {}).get("epss", {}).get(
        "model_version", "")
    return {
        "tool_version": __version__,
        "generated_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds"),
        "sbom": os.path.basename(sbom_path),
        "snapshot": os.path.basename(os.path.normpath(snapshot)),
        "kev_catalog_version": kev_catalog,
        "epss_model_version": epss_model,
        "weights": weights_name,
        "weight_values": weights,
        "p1_threshold": P1_THRESHOLD,
        "counts": {
            "findings": n,
            "components_in_sbom": len(components),
            "components_assessed": len(components) - len(
                [c for c in not_assessed]),
            "components_not_assessed": len(not_assessed),
            "kev_rows": kev_rows,
            "tiers": tiers,
        },
        "coverage": {
            "cvss_pct": round(100 * with_cvss / n, 1) if n else 100.0,
            "epss_pct": round(100 * with_epss / n, 1) if n else 100.0,
        },
        "findings": scored,
        "not_assessed": not_assessed,
    }


HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>iotsentinel triage report</title>
<style>
 body{font-family:system-ui,sans-serif;margin:2rem;background:#fafafa;color:#222}
 h1{font-size:1.3rem} table{border-collapse:collapse;width:100%;background:#fff}
 th,td{border:1px solid #ddd;padding:.35rem .6rem;font-size:.85rem;text-align:left}
 th{background:#eee;cursor:pointer}
 tr.P1{background:#fdd} tr.P2{background:#ffd}
 td.num{text-align:right}
 .meta{color:#555;font-size:.85rem}
</style></head><body>
<h1>iotsentinel triage report</h1>
<p class="meta">$meta</p>
<table id="t">
<thead><tr>
<th data-k="cve">CVE</th><th data-k="component">Component</th>
<th data-k="version">Version</th><th data-k="cvss">CVSS</th>
<th data-k="epss">EPSS</th><th data-k="kev">KEV</th>
<th data-k="score">Score</th><th data-k="tier">Tier</th>
<th data-k="description">Description</th>
</tr></thead>
<tbody>
$rows
</tbody></table>
<p class="meta">$coverage</p>
<script>
document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{
 const t=document.getElementById('t'),i=th.cellIndex;
 [...t.tBodies[0].rows].sort((a,b)=>
   (a.cells[i].textContent>b.cells[i].textContent?1:-1))
   .forEach(r=>t.tBodies[0].appendChild(r));}));
</script>
</body></html>
""")


def render_html(report: dict) -> str:
    rows = []
    for f in report["findings"]:
        cvss = f"{f['cvss']:.1f}" if f["cvss"] is not None else "&mdash;"
        epss = f"{f['epss']:.4f}" if f["epss"] is not None else "&mdash;"
        desc = f["description"].replace("&", "&amp;") \
            .replace("<", "&lt;").replace(">", "&gt;")
        rows.append(
            f'<tr class="{f["tier"]}"><td>{f["cve"]}</td>'
            f'<td>{f["component"]}</td><td>{f["version"]}</td>'
            f'<td class="num">{cvss}</td><td class="num">{epss}</td>'
            f'<td>{"yes" if f["kev"] else "&mdash;"}</td>'
            f'<td class="num">{f["score"]:.3f}</td>'
            f'<td>{f["tier"]}</td><td>{desc}</td></tr>')
    meta = (f"snapshot {report['snapshot']} &middot; "
            f"weights {report['weights']} &middot; "
            f"tool {report['tool_version']} &middot; "
            f"generated {report['generated_utc']} &middot; "
            f"KEV catalog {report['kev_catalog_version'] or '?'} &middot; "
            f"EPSS model {report['epss_model_version'] or '?'}")
    coverage = (f"coverage: CVSS {report['coverage']['cvss_pct']}%, "
                f"EPSS {report['coverage']['epss_pct']}% &middot; "
                f"tiers {report['counts']['tiers']} &middot; "
                f"{report['counts']['components_not_assessed']} components "
                f"not assessed")
    return HTML_TEMPLATE.substitute(meta=meta, rows="\n".join(rows),
                                    coverage=coverage)


def cmd_triage(args) -> int:
    snap = args.snapshot
    if not os.path.isdir(snap):
        print(f"error: snapshot not found: {snap}", file=sys.stderr)
        return 1
    manifest = load_manifest(snap)
    if not manifest:
        print(f"warning: no manifest.json in {snap}", file=sys.stderr)
    try:
        sbom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"error: cannot read SBOM: {exc}", file=sys.stderr)
        return 1
    cpe_map_path = Path(__file__).resolve().parent.parent.parent / \
        "data" / "cpe_map.json"
    if not cpe_map_path.is_file():          # installed without repo data
        cpe_map_path = Path("data/cpe_map.json")
    from .feeds import load_cpe_map
    cpe_map = load_cpe_map(cpe_map_path)
    nvd = load_nvd(snap)
    kev = load_kev(snap)
    epss = load_epss(snap)
    if not nvd:
        print(f"error: no NVD records in {snap}/nvd", file=sys.stderr)
        return 1

    built = find_rows(sbom, cpe_map, nvd, kev, epss)
    report = build_report(args.sbom, snap, built["rows"],
                          built["not_assessed"], args.weights, manifest)
    if args.sensitivity:
        report["sensitivity"] = sensitivity_check(built["rows"])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    counts = report["counts"]
    print(f"triage: {counts['findings']} findings over "
          f"{counts['components_in_sbom']} components "
          f"(assessed {counts['components_assessed']}, "
          f"not assessed {counts['components_not_assessed']})")
    print(f"  tiers: {counts['tiers']}")
    print(f"  coverage: CVSS {report['coverage']['cvss_pct']}%, "
          f"EPSS {report['coverage']['epss_pct']}%")
    if args.sensitivity:
        sens = report["sensitivity"]
        print(f"  sensitivity: {sens['moved_W1_to_W2']}/{sens['n_findings']} "
              f"move W1->W2, {sens['moved_W1_to_W3']}/{sens['n_findings']} "
              f"move W1->W3")
    print(f"  report written to {out}")
    if args.html:
        hp = Path(args.html)
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(render_html(report), encoding="utf-8")
        print(f"  html report written to {hp}")
    return 0
