"""Tests for multi-file zip staging (roadmap #3, 2026-09-11):

orchestrator/sample_types.py::build_staging_zip + sanitize_staged_name —
extract ALL entries of a submitted archive into a staging zip containing
only sanitized relative paths (zip-slip-proof by construction), with the
same read()-only safety contract as resolve_archive_entry.
"""

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from orchestrator.sample_types import (
    ArchiveResolutionError,
    build_staging_zip,
    sanitize_staged_name,
)


def _make_zip(entries):
    """entries: list of (name, bytes). Returns raw zip bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def _read_staging(path):
    with zipfile.ZipFile(path) as zf:
        return {info.filename: zf.read(info.filename) for info in zf.infolist()}


# --- sanitize_staged_name -------------------------------------------------

def test_sanitize_plain_name():
    assert sanitize_staged_name("invoice.exe", set()) == "invoice.exe"


def test_sanitize_traversal_dropped():
    assert sanitize_staged_name("../../evil.dll", set()) == "evil.dll"
    assert sanitize_staged_name("a/../../b/c.dll", set()) == "b/c.dll"


def test_sanitize_drive_and_root_stripped():
    assert sanitize_staged_name("C:/abs/path.dll", set()) == "abs/path.dll"
    assert sanitize_staged_name("/rooted/x.bin", set()) == "rooted/x.bin"


def test_sanitize_unsafe_chars_and_structure_kept():
    assert sanitize_staged_name("da ta/con fig.bin", set()) == "da_ta/con_fig.bin"


def test_sanitize_empty_becomes_file():
    assert sanitize_staged_name("../../", set()) == "file"


def test_sanitize_duplicates_suffixed():
    used = set()
    a = sanitize_staged_name("x.dll", used)
    b = sanitize_staged_name("x.dll", used)
    c = sanitize_staged_name("../x.dll", used)
    assert a == "x.dll" and b == "x.dll-2" and c == "x.dll-3"


def test_sanitize_length_cap():
    long_name = "a" * 200 + ".dll"
    out = sanitize_staged_name(long_name, set())
    assert len(out) <= 120
    assert out.endswith(".dll")


# --- build_staging_zip ----------------------------------------------------

def test_all_entries_staged_with_manifest(tmp_path):
    data = _make_zip([
        ("runner.bat", b"@echo hi"),
        ("payload.dll", b"MZ"),
        ("data/config.bin", b"\x00\x01"),
    ])
    out = tmp_path / "staging.zip"
    manifest = build_staging_zip(data, str(out))
    staged = _read_staging(str(out))
    assert staged == {
        "runner.bat": b"@echo hi",
        "payload.dll": b"MZ",
        "data/config.bin": b"\x00\x01",
    }
    assert len(manifest["entries"]) == 3
    assert manifest["skipped"] == []
    assert manifest["entries"][2]["staged_as"] == "data/config.bin"


def test_traversal_entry_neutralized(tmp_path):
    data = _make_zip([("../../evil.dll", b"MZ"), ("ok.exe", b"MZ2")])
    out = tmp_path / "staging.zip"
    manifest = build_staging_zip(data, str(out))
    staged = _read_staging(str(out))
    assert staged == {"evil.dll": b"MZ", "ok.exe": b"MZ2"}
    assert manifest["entries"][0]["staged_as"] == "evil.dll"


def test_oversize_entry_skipped_and_recorded(tmp_path):
    data = _make_zip([("big.bin", b"x" * 100), ("small.bin", b"y")])
    out = tmp_path / "staging.zip"
    manifest = build_staging_zip(data, str(out), max_entry_size_bytes=50)
    staged = _read_staging(str(out))
    assert staged == {"small.bin": b"y"}
    assert manifest["skipped"] == [{"name": "big.bin", "reason": "entry_too_large"}]


def test_password_protected_zip(tmp_path):
    pyzipper = pytest.importorskip("pyzipper")
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("a.exe", b"MZ")
        zf.writestr("b.dll", b"DLL")
    out = tmp_path / "staging.zip"
    manifest = build_staging_zip(buf.getvalue(), str(out), archive_password="infected")
    staged = _read_staging(str(out))
    assert staged == {"a.exe": b"MZ", "b.dll": b"DLL"}
    assert manifest["skipped"] == []


def test_wrong_password_raises_nothing_staged(tmp_path):
    pyzipper = pytest.importorskip("pyzipper")
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("a.exe", b"MZ")
    out = tmp_path / "staging.zip"
    with pytest.raises(ArchiveResolutionError):
        build_staging_zip(buf.getvalue(), str(out), archive_password="wrong")


def test_invalid_archive_raises(tmp_path):
    with pytest.raises(ArchiveResolutionError):
        build_staging_zip(b"not a zip", str(tmp_path / "s.zip"))


def test_empty_archive_raises(tmp_path):
    with pytest.raises(ArchiveResolutionError):
        build_staging_zip(_make_zip([]), str(tmp_path / "s.zip"))


def test_too_many_entries_raises(tmp_path):
    data = _make_zip([(f"f{i}.bin", b"x") for i in range(5)])
    with pytest.raises(ArchiveResolutionError):
        build_staging_zip(data, str(tmp_path / "s.zip"), max_total_entries=3)
