"""Download a pinned YARA-Forge rules package (core/extended/full) into
out/yara_forge_dl/, ready for scripts/vendor_yara_rules.py.

Modeled on the manual CAPE community zip flow (out/cape_community_dl/) but
scripted so the source+version are reproducible. Records what was fetched in
out/yara_forge_dl/.fetch_label.

Usage:
    python scripts/fetch_yara_forge.py --release 20260830 --tier extended
    python scripts/vendor_yara_rules.py out/yara_forge_dl/<extracted>.yar yara_rules \
        --source-label yara-forge-extended-20260830
"""

import argparse
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DL_DIR = PROJECT_ROOT / "out" / "yara_forge_dl"
API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/tags/{release}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True, help="YARA-Forge release tag, e.g. 20260830")
    ap.add_argument("--tier", choices=["core", "extended", "full"], default="extended")
    args = ap.parse_args()

    DL_DIR.mkdir(parents=True, exist_ok=True)
    asset_name = f"yara-forge-rules-{args.tier}.zip"

    with urllib.request.urlopen(API.format(release=args.release), timeout=30) as resp:
        meta = json.load(resp)
    url = next(
        (a["browser_download_url"] for a in meta.get("assets", []) if a["name"] == asset_name),
        None,
    )
    if not url:
        names = [a["name"] for a in meta.get("assets", [])]
        raise SystemExit(f"asset {asset_name} not found in release {args.release}; has: {names}")

    zip_path = DL_DIR / asset_name
    if not zip_path.exists():
        print(f"downloading {url} -> {zip_path}")
        urllib.request.urlretrieve(url, zip_path)
    else:
        print(f"already downloaded: {zip_path}")

    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(DL_DIR / f"{args.release}-{args.tier}")
        members = zf.namelist()
    print(f"extracted {len(members)} file(s): {[m for m in members][:5]}")

    (DL_DIR / ".fetch_label").write_text(
        f"{asset_name} @ release {args.release} fetched {datetime.now(timezone.utc).isoformat()}\n"
    )
    print(f"label: yara-forge-{args.tier}-{args.release}")


if __name__ == "__main__":
    main()
