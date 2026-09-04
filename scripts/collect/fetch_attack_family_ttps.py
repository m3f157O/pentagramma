"""Fetch family -> ATT&CK technique ground truth from MITRE's public STIX data.

Extracts, for each corpus malware family, the set of techniques that MITRE
ATT&CK's Software entries document for it (public, canonical, verifiable --
exactly the "proven ground truth" the corpus needs). Output is a small
curated JSON, versioned in the repo:

    orchestrator/data/family_ttps.json

    python scripts/collect/fetch_attack_family_ttps.py [--stix <path-or-url>]

The STIX bundle (enterprise-attack.json, ~50MB) is downloaded to
out/attack_stix/ and reused if present.
"""

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUT_DIR = PROJECT_ROOT / "out" / "attack_stix"
DEST = PROJECT_ROOT / "orchestrator" / "data" / "family_ttps.json"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# corpus family (manifest label) -> ATT&CK software entry name
FAMILIES = {
    "emotet": "Emotet",
    "qakbot": "QakBot",
    "agenttesla": "Agent Tesla",
    "redline": "RedLine Stealer",
    "asyncrat": "AsyncRAT",
    "remcos": "Remcos",
}


def load_stix(path_or_url: str) -> dict:
    p = Path(path_or_url)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cached = OUT_DIR / "enterprise-attack.json"
    if not cached.exists():
        print(f"[attack] downloading {path_or_url} -> {cached}")
        urllib.request.urlretrieve(path_or_url, cached)
    return json.loads(cached.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stix", default=STIX_URL, help="path or URL to enterprise-attack.json")
    args = ap.parse_args()

    bundle = load_stix(args.stix)
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects if "id" in o}

    # attack-pattern stix id -> short technique id (Txxxx)
    tech_id = {}
    for o in objects:
        if o.get("type") == "attack-pattern":
            for ref in o.get("external_references") or []:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tech_id[o["id"]] = ref["external_id"]
                    break

    result = {"_source": "MITRE ATT&CK enterprise (STIX)", "_fetched_at": datetime.now(timezone.utc).isoformat()}
    for family, attack_name in FAMILIES.items():
        software = next(
            (o for o in objects
             if o.get("type") in ("malware", "tool") and (o.get("name") or "").lower() == attack_name.lower()),
            None,
        )
        if not software:
            print(f"[attack] WARNING: no software entry for {family} ({attack_name})")
            continue
        techniques = sorted({
            tech_id[rel["target_ref"]]
            for rel in objects
            if rel.get("type") == "relationship"
            and rel.get("relationship_type") == "uses"
            and rel.get("source_ref") == software["id"]
            and rel.get("target_ref") in tech_id
        })
        result[family] = {
            "attack_name": software["name"],
            "attack_id": next((r["external_id"] for r in software.get("external_references", [])
                               if r.get("source_name") == "mitre-attack"), None),
            "techniques": techniques,
            "reference": f"https://attack.mitre.org/software/",
        }
        print(f"[attack] {family:12s} {software['name']:16s} {len(techniques)} techniques: {', '.join(techniques[:8])}...")

    DEST.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(f"\n[attack] -> {DEST}")


if __name__ == "__main__":
    main()
