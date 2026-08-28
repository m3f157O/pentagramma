"""Sample ingestion, storage, and metadata management."""

import hashlib
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import ppdeep

from orchestrator.config import SandboxConfig


class SampleManager:
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.samples_dir = Path(config.paths["samples_dir"])
        self.samples_dir.mkdir(parents=True, exist_ok=True)

    def _compute_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "ssdeep": ppdeep.hash(data),
        }

    def store_sample(
        self,
        filename: str,
        data: bytes,
        source: str = "upload",
        tags: Optional[list] = None,
        sample_type: Optional[str] = None,
    ) -> Dict[str, any]:
        """Store a sample file and return its metadata record.

        sample_type (exe/dll/js/vbs/ps1/bat/zip/unknown, see
        orchestrator/sample_types.py) is metadata-only -- it never affects
        the on-disk dedup scheme below, which stays keyed purely by SHA256.
        """
        file_id = str(uuid.uuid4())
        hashes = self._compute_hashes(data)
        sha256 = hashes["sha256"]

        # Deduplicate by SHA256
        existing = self.samples_dir / sha256[:2] / sha256
        if existing.exists():
            stored_path = existing
        else:
            stored_dir = self.samples_dir / sha256[:2]
            stored_dir.mkdir(parents=True, exist_ok=True)
            stored_path = stored_dir / sha256
            stored_path.write_bytes(data)

        metadata = {
            "id": file_id,
            "filename": filename,
            "source": source,
            "tags": tags or [],
            "sample_type": sample_type,
            "size": len(data),
            "hashes": hashes,
            "stored_path": str(stored_path),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        meta_path = stored_path.with_suffix(".json")
        import json
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        return metadata

    def get_sample_path(self, sha256: str) -> Optional[Path]:
        candidate = self.samples_dir / sha256[:2] / sha256
        if candidate.exists():
            return candidate
        return None

    def get_metadata(self, sha256: str) -> Optional[Dict[str, any]]:
        candidate = self.samples_dir / sha256[:2] / f"{sha256}.json"
        if not candidate.exists():
            return None
        import json
        return json.loads(candidate.read_text(encoding="utf-8"))
