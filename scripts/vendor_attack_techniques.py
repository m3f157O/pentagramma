"""Vendors a minimal MITRE ATT&CK technique-id -> name/tactics lookup into
orchestrator/data/attack_techniques.json, extracted from the official
enterprise-attack STIX bundle (mitre-attack/attack-stix-data).

The full STIX bundle is ~53MB and not something to vendor as-is or fetch
at runtime -- this script downloads it once, extracts only {id: {name,
tactics}} for non-revoked/non-deprecated techniques (~700 entries, a few
tens of KB), and discards the rest. Same "fetch once, vendor the small
derived artifact" pattern as scripts/vendor_sigma_rules.py.

Usage:
    python scripts/vendor_attack_techniques.py [--source-url URL]
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEST_PATH = Path(__file__).resolve().parent.parent / "orchestrator" / "data" / "attack_techniques.json"


def extract_techniques(stix_bundle: dict) -> dict:
    techniques = {}
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break
        if not external_id or not external_id.startswith("T"):
            continue
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[external_id] = {"name": obj.get("name"), "tactics": tactics}
    return techniques


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    args = parser.parse_args()

    print(f"Fetching {args.source_url} ...", file=sys.stderr)
    with urllib.request.urlopen(args.source_url) as resp:
        stix_bundle = json.loads(resp.read().decode("utf-8"))

    techniques = extract_techniques(stix_bundle)
    print(f"Extracted {len(techniques)} techniques", file=sys.stderr)

    DEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEST_PATH.write_text(json.dumps(techniques, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {DEST_PATH} ({DEST_PATH.stat().st_size} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
