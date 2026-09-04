"""Ground-truth linker: attach independently-verifiable IOCs (ThreatFox) to
already-fetched MalwareBazaar samples, so later detonations can be scored
against proven C2 infrastructure instead of just family labels.

For each manifest row under samples/incoming/malwarebazaar/<family>/:
  POST https://threatfox-api.abuse.ch/api/v1/  {"query": "search_hash", "hash": sha256}
and store samples/incoming/malwarebazaar/_groundtruth/<sha256>.json with the
raw IOC list + reference URLs. Resumable (existing files skipped), polite
(1s between calls), never downloads or executes anything.

Also emits the detonation worklist (samples with >= 1 C2-class IOC at
confidence >= MIN_CONFIDENCE) to _groundtruth/worklist.txt.

    python scripts/collect/verify_groundtruth.py            # needs MB_API_KEY
    python scripts/collect/verify_groundtruth.py --summary  # reprint summary only
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
INCOMING = PROJECT_ROOT / "samples" / "incoming" / "malwarebazaar"
GT_DIR = INCOMING / "_groundtruth"

API = "https://threatfox-api.abuse.ch/api/v1/"
API_KEY = os.environ.get("MB_API_KEY", "")
REQUEST_DELAY_S = 1.0
MIN_CONFIDENCE = 50
C2_IOC_TYPES = {"domain", "ip:port", "url", "ip"}


def api_post(data: dict, retries: int = 3) -> dict:
    headers = {"Auth-Key": API_KEY} if API_KEY else {}
    for attempt in range(retries):
        try:
            r = requests.post(API, json=data, headers=headers, timeout=30)
        except requests.RequestException as e:
            wait = 5 * (attempt + 1)
            print(f"  [retry] {data.get('hash', '')[:12]} attempt {attempt + 1}/{retries} ({e}); sleep {wait}s")
            time.sleep(wait)
            continue
        if r.status_code == 401:
            raise SystemExit("[threatfox] 401 Unauthorized: set MB_API_KEY (abuse.ch account API key)")
        r.raise_for_status()
        return r.json()
    return {"query_status": "request_failed"}


def load_manifest_rows():
    for manifest in sorted(INCOMING.glob("*/manifest.jsonl")):
        family = manifest.parent.name
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            row["_family_dir"] = family
            yield row


def c2_iocs(iocs):
    return [i for i in iocs
            if (i.get("ioc_type") or "").lower() in C2_IOC_TYPES
            and int(i.get("confidence_level") or 0) >= MIN_CONFIDENCE]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api-key", default=None, help="abuse.ch API key (or MB_API_KEY env var)")
    ap.add_argument("--summary", action="store_true", help="skip API calls; reprint summary from stored ground truth")
    args = ap.parse_args()

    global API_KEY
    if args.api_key:
        API_KEY = args.api_key
    GT_DIR.mkdir(parents=True, exist_ok=True)

    rows = list(load_manifest_rows())
    print(f"[gt] manifest rows: {len(rows)}")

    if not args.summary:
        if not API_KEY:
            raise SystemExit("[threatfox] no API key: set MB_API_KEY or --api-key")
        done = skipped = 0
        for row in rows:
            sha = row.get("sha256")
            if not sha:
                continue
            out_path = GT_DIR / f"{sha}.json"
            if out_path.exists():
                skipped += 1
                continue
            j = api_post({"query": "search_hash", "hash": sha})
            time.sleep(REQUEST_DELAY_S)
            iocs = []
            if j.get("query_status") == "ok":
                for d in j.get("data") or []:
                    iocs.append({
                        "ioc_type": d.get("ioc_type"),
                        "ioc": d.get("ioc"),
                        "threat_type": d.get("threat_type"),
                        "confidence_level": d.get("confidence_level"),
                        "reference": d.get("reference"),
                        "reporter": d.get("reporter"),
                    })
            out_path.write_text(json.dumps({
                "sha256": sha,
                "family": row.get("family") or row.get("_family_dir"),
                "bazaar_url": f"https://bazaar.abuse.ch/sample/{sha}/",
                "threatfox_query_status": j.get("query_status"),
                "threatfox_iocs": iocs,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }, indent=1), encoding="utf-8")
            done += 1
            if done % 10 == 0:
                print(f"[gt] {done} queried ({skipped} cached)...")
        print(f"[gt] queried {done}, cached {skipped}")

    # Summary + worklist from stored ground truth.
    per_family = {}
    worklist = []
    for gt_path in sorted(GT_DIR.glob("*.json")):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        fam = gt.get("family") or "?"
        stats = per_family.setdefault(fam, {"total": 0, "with_c2": 0})
        stats["total"] += 1
        hits = c2_iocs(gt.get("threatfox_iocs") or [])
        if hits:
            stats["with_c2"] += 1
            zip_path = INCOMING / fam / f"{gt['sha256']}.zip"
            if zip_path.exists():
                worklist.append(str(zip_path))
    print("\n[gt] per-family ground truth (C2 IOC @ confidence >= %d):" % MIN_CONFIDENCE)
    for fam in sorted(per_family):
        s = per_family[fam]
        print(f"  {fam:12s} {s['with_c2']:3d}/{s['total']:3d} samples with verifiable C2")
    wl_path = GT_DIR / "worklist.txt"
    wl_path.write_text("\n".join(worklist) + "\n", encoding="utf-8")
    print(f"\n[gt] detonation worklist: {len(worklist)} samples -> {wl_path}")


if __name__ == "__main__":
    main()
