"""feeds: fetch and load the dated vulnerability-feed snapshots.

`fetch` downloads three feeds and writes them to
`data/snapshots/<YYYY-MM-DD>/` with a `manifest.json` recording URLs,
fetch timestamps, SHA-256 checksums, the KEV catalogVersion and the EPSS
model version. Nothing else in the tool touches the network.

Feed sources (verify the URLs in a browser before relying on them):
- CISA KEV: known_exploited_vulnerabilities.json
- EPSS: daily csv.gz score file (the FIRST_ORGANIZATION publishes it at
  epss.empiricalsecurity.com; epss.cyentia.com redirects there)
- NVD: CVE API 2.0, rate limited (5 requests / 30 s without an API key)

Large downloads are kept out of git (`.gitignore` covers `*full*`); the
committed snapshot is the reduced form: KEV/EPSS rows only for the CVEs
the NVD queries returned for the CPE map, plus the trimmed NVD records.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

USER_AGENT = f"iotsentinel/{__version__} (research tool; stdlib-only)"


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------- fetching

def fetch_kev() -> tuple[dict, bytes]:
    blob = http_get(KEV_URL)
    data = json.loads(blob)
    return data, blob


def fetch_epss(date: str) -> tuple[str, list[tuple[str, float, float]], bytes]:
    """Return (model_version, rows, raw_bytes). Rows: (cve, epss, percentile)."""
    blob = http_get(EPSS_URL.format(date=date))
    text = gzip.decompress(blob).decode("utf-8", "replace")
    model_version = ""
    rows: list[tuple[str, float, float]] = []
    header: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("#"):
            if "model:" in line:
                model_version = line.split("model:", 1)[1].strip()
            continue
        if not line.strip():
            continue
        if header is None:
            header = [c.strip() for c in line.split(",")]
            continue
        values = dict(zip(header, line.split(",")))
        try:
            rows.append((values["cve"], float(values["epss"]),
                         float(values.get("percentile", 0.0) or 0.0)))
        except (KeyError, ValueError):
            continue
    return model_version, rows, blob


def fetch_nvd_cpe(cpe_name: str, results_per_page: int = 2000) -> dict:
    """Query NVD CVE API 2.0 for all CVEs matching a CPE product (wildcard
    version); version filtering happens locally in triage."""
    import urllib.parse
    url = (f"{NVD_URL}?cpeName={urllib.parse.quote(cpe_name)}"
           f"&resultsPerPage={results_per_page}")
    blob = http_get(url, timeout=90)
    return json.loads(blob)


def load_cpe_map(path: str | os.PathLike) -> dict[str, str]:
    """package name -> 'vendor:product'."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_fetch(args) -> int:
    date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snap = Path(args.snapshots_dir) / date
    snap.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "tool_version": __version__,
        "snapshot_date": date,
        "feeds": {},
    }

    print(f"fetch: snapshot {date} -> {snap}")

    # CISA KEV
    print("  downloading CISA KEV ...")
    kev, kev_blob = fetch_kev()
    (snap / "kev.full.json").write_bytes(kev_blob)
    manifest["feeds"]["kev"] = {
        "url": KEV_URL,
        "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": sha256_bytes(kev_blob),
        "catalog_version": kev.get("catalogVersion", ""),
        "date_released": kev.get("dateReleased", ""),
        "count": kev.get("count", len(kev.get("vulnerabilities", []))),
    }

    # EPSS
    print("  downloading EPSS ...")
    # EPSS publishes the previous day's file; step back until a file exists.
    epss_model, epss_rows, epss_blob = None, None, None
    epss_date = date
    from datetime import timedelta
    for _ in range(5):
        try:
            epss_model, epss_rows, epss_blob = fetch_epss(epss_date)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                epss_date = (datetime.strptime(epss_date, "%Y-%m-%d")
                             - timedelta(days=1)).strftime("%Y-%m-%d")
                continue
            raise
    if epss_blob is None:
        print("error: no EPSS file found for the last 5 days", file=sys.stderr)
        return 1
    (snap / "epss.full.csv.gz").write_bytes(epss_blob)
    manifest["feeds"]["epss"] = {
        "url": EPSS_URL.format(date=epss_date),
        "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": sha256_bytes(epss_blob),
        "model_version": epss_model,
        "score_date": epss_date,
        "rows": len(epss_rows),
    }

    # NVD, per CPE product (wildcard version), respecting the rate limit
    cpe_map = load_cpe_map("data/cpe_map.json")
    products = sorted({spec.split(":", 1)[1] for spec in cpe_map.values()
                       if ":" in spec})
    nvd_dir = snap / "nvd"
    nvd_dir.mkdir(exist_ok=True)
    manifest["feeds"]["nvd"] = {"url": NVD_URL, "queries": {}}
    n_rows = len(products)
    for i, product in enumerate(products, 1):
        vendor = next(v for v, p in
                      (spec.split(":", 1) for spec in cpe_map.values())
                      if p == product)
        cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
        out = nvd_dir / f"{vendor}__{product}.json"
        print(f"  NVD {i}/{n_rows}: {vendor}:{product} ...")
        try:
            data = fetch_nvd_cpe(cpe)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) \
                as exc:
            print(f"    warning: {product}: {exc}", file=sys.stderr)
            data = {"error": str(exc), "vulnerabilities": []}
        (out).write_text(json.dumps(data) + "\n", encoding="utf-8")
        manifest["feeds"]["nvd"]["queries"][f"{vendor}:{product}"] = {
            "cpe": cpe,
            "total_results": data.get("totalResults", 0),
            "fetched_utc": datetime.now(timezone.utc)
            .isoformat(timespec="seconds"),
        }
        if i < n_rows:
            time.sleep(args.nvd_sleep)

    (snap / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                        encoding="utf-8")
    print(f"fetch: manifest written ({len(epss_rows)} EPSS rows, "
          f"KEV catalog {manifest['feeds']['kev']['catalog_version']})")
    return 0


# ----------------------------------------------------------------- loading

def load_kev(snap: str | os.PathLike) -> dict[str, dict]:
    """CVE id -> KEV record. Prefers the reduced kev.json, falls back to
    the full file."""
    path = Path(snap)
    for name in ("kev.json", "kev.full.json"):
        p = path / name
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    return {}


def load_epss(snap: str | os.PathLike) -> dict[str, float]:
    """CVE id -> EPSS probability. Prefers the reduced epss.csv."""
    path = Path(snap)
    p = path / "epss.csv"
    if p.is_file():
        with open(p, encoding="utf-8") as f:
            return {row["cve"]: float(row["epss"])
                    for row in csv.DictReader(f)
                    if row.get("cve", "").startswith("CVE-")}
    full = path / "epss.full.csv.gz"
    if full.is_file():
        text = gzip.decompress(full.read_bytes()).decode("utf-8", "replace")
        out: dict[str, float] = {}
        header: list[str] | None = None
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            if header is None:
                header = [c.strip() for c in line.split(",")]
                continue
            values = dict(zip(header, line.split(",")))
            if values.get("cve", "").startswith("CVE-"):
                try:
                    out[values["cve"]] = float(values["epss"])
                except ValueError:
                    continue
        return out
    return {}


def load_nvd(snap: str | os.PathLike) -> dict[str, dict]:
    """'vendor:product' -> {'records': [trimmed cve record], ...}.

    The trimmed records live in nvd/*.json as produced by reduce_snapshot;
    raw API pages also load (records extracted on the fly) so triage works
    straight after a fetch.
    """
    nvd_dir = Path(snap) / "nvd"
    out: dict[str, dict] = {}
    if not nvd_dir.is_dir():
        return out
    for p in sorted(nvd_dir.glob("*.json")):
        key = p.stem.replace("__", ":")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if "records" in data:          # reduced form
            out[key] = data
        else:                          # raw NVD API page
            out[key] = {"records": [trim_nvd_item(it["cve"])
                                    for it in data.get("vulnerabilities", [])
                                    if "cve" in it]}
    return out


def trim_nvd_item(cve: dict) -> dict:
    """Reduce an NVD 2.0 CVE object to what triage needs."""
    score = None
    for metric in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric) or []
        if metrics:
            score = metrics[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                break
    criteria = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            if not node.get("operator", "OR").upper() == "OR":
                continue
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", False):
                    continue
                crit = {"cpe": m.get("criteria", "")}
                for field in ("versionStartIncluding", "versionStartExcluding",
                              "versionEndIncluding", "versionEndExcluding"):
                    if field in m:
                        crit[field] = m[field]
                criteria.append(crit)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:300]
            break
    return {
        "id": cve.get("id", ""),
        "published": (cve.get("published") or "")[:10],
        "cvss": score,
        "criteria": criteria,
        "description": desc,
    }


def load_manifest(snap: str | os.PathLike) -> dict:
    p = Path(snap) / "manifest.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}
