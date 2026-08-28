"""Shared helpers for corpus acquisition fetchers (workstream A1).

Rules every fetcher follows:
  * NEVER execute what it downloads -- fetch + store only.
  * Malware stays in its passworded zip ("infected") until detonation
    time, so host AV doesn't quarantine it (the detonation pipeline
    already handles passworded zips via orchestrator/sample_types.py).
  * Dedup by sha256 against what is already on disk.
  * Size caps so one prolific family can't drown the corpus.
  * Every stored sample gets a manifest.jsonl row so labeling/splitting
    can be seeded later without re-fetching.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, Set

# Hard safety caps (overridable per-fetcher but never removed).
MAX_FILE_BYTES = 100 * 1024 * 1024       # 100 MB per sample
MAX_TOTAL_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB per fetch run


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_hashes(root: str) -> Set[str]:
    """sha256s already recorded in any manifest under root (dedup across
    runs without re-hashing large trees)."""
    out: Set[str] = set()
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name != "manifest.jsonl":
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                    for line in f:
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        for key in ("sha256", "zip_sha256"):
                            if row.get(key):
                                out.add(row[key])
            except OSError:
                continue
    return out


def append_manifest(out_dir: str, row: Dict) -> None:
    """Append one manifest row. Required fields: source, sha256, intended_label."""
    row = dict(row)
    row.setdefault("fetched_at", datetime.now(timezone.utc).isoformat())
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def store_bytes(out_dir: str, filename: str, data: bytes, max_bytes: int = MAX_FILE_BYTES) -> Optional[str]:
    """Write a sample blob under out_dir with the size cap enforced."""
    if len(data) > max_bytes:
        return None
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path
