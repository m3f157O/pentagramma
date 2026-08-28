"""Environment dressing for the analysis VM golden image (anti-sandbox realism).

Run in the guest via PSDirect (orchestrator provision-dressing endpoint):

    python apply_dressing.py apply    # create artifacts (idempotent)
    python apply_dressing.py verify   # exit 0 iff artifacts are present

Creates a believable used-user profile for gigi: documents/downloads/desktop
files with real minimal formats, browser history/bookmarks (Edge, sqlite),
recent-run artifacts (RunMRU, TypedPaths) and Recent-folder shortcuts.
Best-effort per item — one failure never aborts the rest.

NOT covered (documented limitation): system uptime (fresh boot every run —
cannot be faked without hypervisor time control).
"""
import json
import os
import sqlite3
import sys
import time
import winreg
import zipfile

USERPROFILE = os.environ.get("USERPROFILE", r"C:\Users\gigi")

# A spread of believable user files. Kinds: txt/csv/pdf/docx/xlsx/png.
FILES = [
    (r"Documents\Q3_budget_review.xlsx", "xlsx"),
    (r"Documents\meeting_notes_2026-07-14.docx", "docx"),
    (r"Documents\project_roadmap.docx", "docx"),
    (r"Documents\invoice_ACME_march.pdf", "pdf"),
    (r"Documents\todo.txt", "txt"),
    (r"Documents\shopping_list.txt", "txt"),
    (r"Documents\IT\vpn_setup_notes.txt", "txt"),
    (r"Documents\IT\server_inventory.csv", "csv"),
    (r"Downloads\7z2408-x64.msi", "bin"),
    (r"Downloads\statement_june.pdf", "pdf"),
    (r"Downloads\conference_ticket.pdf", "pdf"),
    (r"Desktop\quick_notes.txt", "txt"),
    (r"Pictures\holiday_lake.png", "png"),
    (r"Pictures\ Screenshots\screenshot_2026-07-20.png", "png"),
    (r"Music\.keep", "txt"),
]

TEXT = {
    "todo.txt": "- renew domain certs\n- call accountant re: Q2 invoices\n- update lab VM images\n- book flights for October\n",
    "shopping_list.txt": "coffee\nolive oil\nbatteries AA\nprinter paper\n",
    "vpn_setup_notes.txt": "1. install openvpn client\n2. copy gigi.ovpn from share\n3. import, connect, test with ping 10.8.0.1\n",
}

RUN_MRU = [("a", r"cmd\1"), ("b", r"notepad todo.txt\1"), ("c", r"ipconfig /all\1"), ("d", r"mstsc\1")]
TYPED_PATHS = ["C:\\Users\\gigi\\Documents", "\\\\fileserver\\share", "C:\\Temp"]

_EDGE_PROFILE = os.path.join(USERPROFILE, r"AppData\Local\Microsoft\Edge\User Data\Default")
_EDGE_URLS = [
    ("https://www.google.com/", "Google", 4),
    ("https://mail.google.com/", "Gmail", 3),
    ("https://github.com/", "GitHub", 2),
    ("https://stackoverflow.com/", "Stack Overflow", 2),
    ("https://www.reddit.com/", "reddit", 1),
]
# Chrome/Edge time: microseconds since 1601-01-01
_EPOCH_DELTA_US = 11644473600000000


def _chrome_ts(days_ago: float) -> int:
    return int((time.time() - days_ago * 86400) * 1_000_000) + _EPOCH_DELTA_US


def _write_docx(path: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Notes from the sync. Action items in todo.txt.</w:t></w:r></w:p></w:body></w:document>')


def _write_xlsx(path: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Item</t></is></c><c r="B1" t="inlineStr"><is><t>Cost</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>VM host hardware</t></is></c><c r="B2"><v>4200</v></c></row></sheetData></worksheet>')


def _write_pdf(path: str) -> None:
    body = b"BT /F1 12 Tf 40 700 Td (Invoice - services rendered, March.) Tj ET"
    pdf = (b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
           b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
           b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
           b"4 0 obj<</Length " + str(len(body)).encode() + b">>stream\n" + body + b"\nendstream endobj\n"
           b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
           b"trailer<</Root 1 0 R>>\n%%EOF\n")
    with open(path, "wb") as f:
        f.write(pdf)


_PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c626001000000ffff03000006000557bfabd40000000049454e44ae426082"
)


def _seed_edge() -> str:
    if not os.path.isdir(os.path.dirname(_EDGE_PROFILE)):
        return "edge-not-installed"
    os.makedirs(_EDGE_PROFILE, exist_ok=True)
    hist = os.path.join(_EDGE_PROFILE, "History")
    if not os.path.exists(hist):
        con = sqlite3.connect(hist)
        try:
            con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0, last_visit_time INTEGER, hidden INTEGER DEFAULT 0)")
            con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER DEFAULT 0, segment_id INTEGER, visit_duration INTEGER DEFAULT 0)")
            for i, (url, title, vc) in enumerate(_EDGE_URLS, start=1):
                con.execute("INSERT INTO urls VALUES (?,?,?,?,0,?,0)", (i, url, title, vc, _chrome_ts(i * 1.3)))
                for v in range(vc):
                    con.execute("INSERT INTO visits (url, visit_time, from_visit, transition) VALUES (?,?,0,805306368)", (i, _chrome_ts(i * 1.3 + v * 0.2)))
            con.commit()
        finally:
            con.close()
    bookmarks = {
        "roots": {"bookmark_bar": {"children": [
            {"type": "url", "name": "GitHub", "url": "https://github.com/"},
            {"type": "url", "name": "Gmail", "url": "https://mail.google.com/"},
            {"type": "url", "name": "Intranet", "url": "http://intranet.corp.local/"},
        ]}},
        "version": 1,
    }
    with open(os.path.join(_EDGE_PROFILE, "Bookmarks"), "w", encoding="utf-8") as f:
        json.dump(bookmarks, f)
    return "ok"


def _seed_registry() -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") as k:
        for name, val in RUN_MRU:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
        winreg.SetValueEx(k, "MRUList", 0, winreg.REG_SZ, "dacb")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths") as k:
        for i, p in enumerate(TYPED_PATHS, start=1):
            winreg.SetValueEx(k, f"url{i}", 0, winreg.REG_SZ, p)


def _seed_recent_shortcuts() -> str:
    try:
        import pythoncom  # noqa: F401
        import win32com.client
    except ImportError:
        return "pywin32-missing"
    recent = os.path.join(USERPROFILE, r"AppData\Roaming\Microsoft\Windows\Recent")
    os.makedirs(recent, exist_ok=True)
    shell = win32com.client.Dispatch("WScript.Shell")
    for name in ("todo.txt", "Q3_budget_review.xlsx", "vpn_setup_notes.txt"):
        lnk = shell.CreateShortcut(os.path.join(recent, name + ".lnk"))
        lnk.TargetPath = os.path.join(USERPROFILE, "Documents", name)
        lnk.save()
    return "ok"


def apply() -> dict:
    results = {"files": [], "errors": []}
    for rel, kind in FILES:
        path = os.path.join(USERPROFILE, rel.strip())
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            name = os.path.basename(path)
            if kind in ("txt", "csv"):
                content = TEXT.get(name, "header1,header2\nvalue1,value2\n" if kind == "csv" else "notes\n")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            elif kind == "docx":
                _write_docx(path)
            elif kind == "xlsx":
                _write_xlsx(path)
            elif kind == "pdf":
                _write_pdf(path)
            elif kind == "png":
                with open(path, "wb") as f:
                    f.write(_PNG_1PX)
            else:  # bin — placeholder content, not a real executable
                with open(path, "wb") as f:
                    f.write(b"7z archive placeholder (dressed sample file)\x00" * 64)
            results["files"].append(rel)
        except Exception as exc:  # noqa: BLE001 — best-effort dressing
            results["errors"].append(f"{rel}: {exc}")
    for step, fn in (("edge", _seed_edge), ("registry", _seed_registry), ("recent", _seed_recent_shortcuts)):
        try:
            results[step] = fn() if step != "registry" else "ok" if not fn() else "ok"
        except Exception as exc:  # noqa: BLE001
            results[step] = f"error: {exc}"
    return results


def verify() -> dict:
    missing = [rel for rel, _ in FILES[:12] if not os.path.exists(os.path.join(USERPROFILE, rel.strip()))]
    reg_ok = True
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") as k:
            winreg.QueryValueEx(k, "a")
    except OSError:
        reg_ok = False
    edge_ok = os.path.exists(os.path.join(_EDGE_PROFILE, "History")) or not os.path.isdir(os.path.dirname(_EDGE_PROFILE))
    return {"missing_files": missing, "runmru": reg_ok, "edge": edge_ok,
            "ok": not missing and reg_ok and edge_ok}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "apply"
    if mode == "apply":
        out = apply()
    elif mode == "verify":
        out = verify()
    else:
        print(f"unknown mode {mode}")
        sys.exit(2)
    print(json.dumps(out, indent=2))
    sys.exit(0 if (mode != "verify" or out.get("ok")) else 1)
