"""C2-recall verification: score our reports against abuse.ch ground truth.

For every detonated sample with stored ThreatFox ground truth
(samples/incoming/malwarebazaar/_groundtruth/<sha256>.json), compare the
report's observed network indicators against the known-C2 IOC list.

Match kinds (most to least direct):
  - "connection": sample-scoped NetworkConnect to a known ip(:port)
  - "dns_query":   DnsQuery for a known C2 domain (counts even if the C2 is
                   dead -- the lookup attempt proves the sample tried)
  - "strings":     IOC value present in static strings (config extraction
                   residue -- noted but NOT counted as observed contact)

A sample with zero matched AND zero DNS/connection attempts at all is
"inconclusive" (never beaconed in the run window), excluded from recall
denominators -- not silently counted as a detection failure.

    .venv/Scripts/python.exe scripts/verify_c2_recall.py [--json out/c2_recall.json]
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.label_from_manifests import _report_head  # noqa: E402

GT_DIR = PROJECT_ROOT / "samples" / "incoming" / "malwarebazaar" / "_groundtruth"
REPORTS = PROJECT_ROOT / "reports"
MIN_CONFIDENCE = 50
C2_IOC_TYPES = {"domain", "ip:port", "ip", "url"}


def _norm_ioc(ioc_type: str, value: str):
    """Split a ThreatFox IOC into matchable (domain, ip, port) parts."""
    value = (value or "").strip().lower()
    if not value:
        return None
    if ioc_type == "domain":
        return {"domain": value}
    if ioc_type == "ip:port":
        ip, _, port = value.partition(":")
        return {"ip": ip, "port": port}
    if ioc_type == "ip":
        return {"ip": value}
    if ioc_type == "url":
        # strip scheme/path -> host part
        host = value.split("://", 1)[-1].split("/")[0].split(":")[0]
        return {"domain": host, "url": value}
    return None


def report_indicators(report: dict):
    """Observed network indicators from a report, sample-scoped where known."""
    ioc = report.get("ioc_summary") or {}
    ips, ports, domains = set(), {}, set()
    for c in ioc.get("network_connections") or []:
        if isinstance(c, dict):
            if c.get("in_sample_scope") is False:
                continue
            ip = (c.get("ip") or c.get("DestinationIp") or "").lower()
            port = str(c.get("port") or c.get("DestinationPort") or "")
        else:
            ip, port = str(c).lower(), ""
        if ip:
            ips.add(ip)
            ports.setdefault(ip, set()).add(port)
    for d in ioc.get("domains") or []:
        name = (d.get("QueryName") if isinstance(d, dict) else str(d)) or ""
        if name:
            domains.add(str(name).lower().rstrip("."))
    # raw DNS telemetry as a fallback (ioc_summary may dedup differently)
    for e in report.get("events") or []:
        if e.get("event_type") == "DnsQuery":
            q = ((e.get("data") or {}).get("QueryName") or "").lower().rstrip(".")
            if q:
                domains.add(q)
    return ips, ports, domains


def evaluate_sample(gt: dict, report: dict) -> dict:
    ips, ports, domains = report_indicators(report)
    results = []
    for ioc in gt.get("threatfox_iocs") or []:
        ioc_type = (ioc.get("ioc_type") or "").lower()
        if ioc_type not in C2_IOC_TYPES or int(ioc.get("confidence_level") or 0) < MIN_CONFIDENCE:
            continue
        parts = _norm_ioc(ioc_type, ioc.get("ioc"))
        if not parts:
            continue
        kind = None
        if parts.get("ip") and parts["ip"] in ips:
            if not parts.get("port") or parts["port"] in ports.get(parts["ip"], set()):
                kind = "connection"
        if not kind and parts.get("domain") and parts["domain"] in domains:
            kind = "dns_query"
        results.append({
            "ioc": ioc.get("ioc"), "ioc_type": ioc_type,
            "confidence": ioc.get("confidence_level"), "matched": bool(kind),
            "match_kind": kind,
        })
    attempted = bool(ips or domains)
    matched = [r for r in results if r["matched"]]
    if not results:
        verdict = "no_groundtruth_iocs"
    elif matched:
        verdict = "observed"
    elif attempted:
        verdict = "missed"
    else:
        verdict = "inconclusive"
    return {"sha256": gt["sha256"], "family": gt.get("family"), "verdict": verdict,
            "matched": len(matched), "total_iocs": len(results), "iocs": results}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", default=str(PROJECT_ROOT / "out" / "c2_recall.json"))
    args = ap.parse_args()

    # sha256 -> latest report
    report_by_sha = {}
    for rp in sorted(REPORTS.glob("*.json")):
        if rp.stem.endswith(".summary"):
            continue
        sha, ts = _report_head(rp)
        if sha and (sha not in report_by_sha or ts > report_by_sha[sha][0]):
            report_by_sha[sha] = (ts, rp)

    per_family = {}
    rows = []
    for gt_path in sorted(GT_DIR.glob("*.json")):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        sha = gt.get("sha256", "").lower()
        if sha not in report_by_sha:
            continue
        report = json.loads(report_by_sha[sha][1].read_text(encoding="utf-8", errors="replace"))
        res = evaluate_sample(gt, report)
        res["report_id"] = report_by_sha[sha][1].stem
        res["sandbox_verdict"] = (report.get("verdict") or {}).get("level")
        rows.append(res)
        fam = res.get("family") or "?"
        agg = per_family.setdefault(fam, {"observed": 0, "missed": 0, "inconclusive": 0, "iocs_matched": 0, "iocs_total": 0})
        if res["verdict"] in ("observed", "missed", "inconclusive"):
            agg[res["verdict"]] += 1
        agg["iocs_matched"] += res["matched"]
        agg["iocs_total"] += res["total_iocs"]

    print(f"{'family':<14} {'observed':>8} {'missed':>7} {'inconcl.':>9} {'C2 IOC recall':>14}")
    print("-" * 60)
    tot = {"observed": 0, "missed": 0, "inconclusive": 0, "iocs_matched": 0, "iocs_total": 0}
    for fam in sorted(per_family):
        a = per_family[fam]
        for k in tot:
            tot[k] += a[k]
        recall = f"{a['iocs_matched']}/{a['iocs_total']}"
        print(f"{fam:<14} {a['observed']:>8} {a['missed']:>7} {a['inconclusive']:>9} {recall:>14}")
    print("-" * 60)
    print(f"{'TOTAL':<14} {tot['observed']:>8} {tot['missed']:>7} {tot['inconclusive']:>9} "
          f"{str(tot['iocs_matched'] / tot['iocs_total'] if tot['iocs_total'] else 0)[:4]:>14}")

    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"per_family": per_family, "samples": rows}, indent=1), encoding="utf-8")
    print(f"\n-> {out_path}")


if __name__ == "__main__":
    main()
