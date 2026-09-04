"""Static analysis module for sandbox samples.

Supports:
  - File type identification
  - PE parsing (headers, sections, imports, exports, resources)
  - .NET/CLR metadata (assembly, typerefs, user strings, obfuscator hints)
  - String extraction (ASCII/Unicode)
  - Entropy calculation
  - YARA rule matching
  - Authenticode signature check
  - Optional VirusTotal lookup
"""

import hashlib
import math
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import filetype
import pefile
import ppdeep

from orchestrator import capa_analysis, detectors

# Matches yara/suspicious_strings.yar's high_entropy_section rule, so the
# static-analysis "packed" verdict agrees with what the YARA layer already flags.
HIGH_ENTROPY_THRESHOLD = 7.2
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# YARA rules are applied in three places across a run, not just to the static
# sample -- surfaced in the rules-catalog UI so it's clear the same ruleset
# covers dropped/unpacked content too.
_YARA_TARGETS = ["submitted sample (static)", "process/memory dumps", "dropped files"]

# Common external variables that on-disk-scan YARA rules gate on. Declaring
# them (with empty defaults) at compile time prevents "undefined identifier"
# compile failures across a large vendored ruleset (e.g. YARA-Forge rules that
# reference `filename`/`extension`); the real per-file values are supplied at
# match time in match_yara(). Match externals must be a subset of the ones
# declared at compile, which is why the same keys appear in both places.
_YARA_EXTERNALS: Dict[str, str] = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}

# Above this many catalogued rules, /api/rules stops embedding raw rule source
# (which would balloon to multiple MB for a vendored ruleset) and the browser
# fetches a rule's source lazily via /api/rules/yara/{name}/raw -- mirroring the
# Sigma catalog's list_rules()/get_rule_yaml() split.
_YARA_CATALOG_INLINE_SOURCE_MAX = 300

_YARA_RULE_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)", re.MULTILINE)
_YARA_DESC_RE = re.compile(r'description\s*=\s*"([^"]*)"')


def _normalize_yara_dirs(yara_rules_dirs: Any) -> List[Path]:
    """Accept a single dir (Path/str) or an iterable of them; return the
    existing directories among them. None-safe."""
    if yara_rules_dirs is None:
        return []
    if isinstance(yara_rules_dirs, (str, Path)):
        yara_rules_dirs = [yara_rules_dirs]
    dirs: List[Path] = []
    for d in yara_rules_dirs:
        if not d:
            continue
        p = Path(d)
        if p.is_dir():
            dirs.append(p)
    return dirs


def _iter_yara_files(yara_rules_dirs: Any):
    """Yield (base_dir, path) for every .yar/.yara file under the given dirs,
    recursively -- vendored rulesets nest rules in category subdirectories the
    way sigma_rules/ does, so a flat glob would miss almost all of them."""
    for base in _normalize_yara_dirs(yara_rules_dirs):
        for path in sorted(base.rglob("*.yar")) + sorted(base.rglob("*.yara")):
            if path.is_file():
                yield base, path


def _iter_yara_rule_blocks(text: str):
    """Yield (rule_name, source_block) for each rule in a .yar file's text,
    slicing between consecutive rule headers so each rule's meta/source stays
    within its own block."""
    matches = list(_YARA_RULE_RE.finditer(text))
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        yield match.group(1), text[start:end].rstrip()


def describe_yara_rules(yara_rules_dirs: Any) -> List[Dict[str, Any]]:
    """Light-parse the vendored .yar files for the rules-catalog UI: rule
    name + description + which targets they run against. A text parse (not the
    compiled yara object) because yara-python doesn't expose rule metadata
    without a match, and this keeps the catalog independent of a compile.

    Accepts a single dir or several (vendored + custom). Raw `source` is
    embedded only for small rulesets; past _YARA_CATALOG_INLINE_SOURCE_MAX it
    is set to None and fetched lazily (get_yara_rule_source) so /api/rules
    stays lean at vendored scale.
    """
    rules: List[Dict[str, Any]] = []
    for base, path in _iter_yara_files(yara_rules_dirs):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = path.name
        for name, block in _iter_yara_rule_blocks(text):
            desc_m = _YARA_DESC_RE.search(block)
            rules.append(
                {
                    "id": f"yara.{name}",
                    "family": detectors.FAMILY_YARA,
                    "name": name,
                    "description": desc_m.group(1) if desc_m else None,
                    "file": rel,
                    "targets": list(_YARA_TARGETS),
                    "source": block,
                }
            )
    if len(rules) > _YARA_CATALOG_INLINE_SOURCE_MAX:
        for r in rules:
            r["source"] = None
    return rules


def get_yara_rule_source(rule_name: str, yara_rules_dirs: Any) -> Optional[str]:
    """Return the raw source of a single YARA rule by name, read lazily from
    disk -- the counterpart to describe_yara_rules() dropping inline source at
    scale (mirrors sigma_engine.get_rule_yaml)."""
    for _base, path in _iter_yara_files(yara_rules_dirs):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, block in _iter_yara_rule_blocks(text):
            if name == rule_name:
                return block
    return None


def describe_static_signals() -> List[Dict[str, Any]]:
    """Inventory of the static-analysis signals that feed detection/verdict,
    in the standardized detector schema (id/family/severity -- see
    orchestrator/detectors.py)."""
    return [
        {
            "id": "static.packing",
            "family": detectors.FAMILY_STATIC,
            "name": "High-entropy / packing",
            "severity": "medium",
            "description": (
                f"Whole-file or executable-section Shannon entropy above "
                f"{HIGH_ENTROPY_THRESHOLD} flags likely packed/encrypted content "
                "(sets packed_suspected; +10 to the verdict)."
            ),
        },
        {
            "id": "static.signature",
            "family": detectors.FAMILY_STATIC,
            "name": "Authenticode signature",
            "severity": "low",
            "description": "Whether the PE is validly signed; unsigned binaries add +5 to the verdict.",
        },
        {
            "id": "static.yara",
            "family": detectors.FAMILY_STATIC,
            "name": "Static YARA match",
            "severity": "high",
            "description": "Any YARA rule matching the submitted binary itself adds +15 to the verdict.",
        },
        {
            "id": "static.pe-structure",
            "family": detectors.FAMILY_STATIC,
            "name": "PE structure",
            "severity": "informational",
            "description": (
                "Informational: sections (name/size/entropy), imports/exports, "
                "imphash, resources -- context, not scored on its own."
            ),
        },
        {
            "id": "static.capa",
            "family": detectors.FAMILY_STATIC,
            "name": "capa capabilities",
            "severity": "medium",
            "description": (
                "Static capability detection (flare-capa, ~1000 rules): names what "
                "the PE can do, mapped to MITRE ATT&CK and MBC. Mostly informational, "
                "but a high-signal capability (injection, anti-analysis, ransomware "
                f"crypto, C2, ...) adds +{detectors.STATIC_CAPA_SIGNAL_WEIGHT} to the verdict."
            ),
        },
    ]


class StaticAnalyzer:
    """Analyze a sample file without executing it."""

    def __init__(
        self,
        yara_rules_dir: Optional[Path] = None,
        custom_rules_dirs: Optional[List[Path]] = None,
        vt_api_key: Optional[str] = None,
        capa_config: Optional[Dict[str, Any]] = None,
    ):
        self.yara_rules_dir = Path(yara_rules_dir) if yara_rules_dir else None
        self.custom_rules_dirs: List[Path] = [Path(d) for d in (custom_rules_dirs or [])]
        self.vt_api_key = vt_api_key
        # capa capability analysis config (rules_dir/sigs_dir/timeout/enabled);
        # empty/disabled by default so the catalog's analyzer and the __main__
        # helper below don't pay capa's cost.
        self.capa_config: Dict[str, Any] = capa_config or {}
        # Fast path: one compiled Rules object for the whole ruleset.
        self._yara_rules: Any = None
        # Fallback path: [(namespace, Rules)] when the combined compile failed
        # and we fell back to per-file isolation (see _load_yara_rules).
        self._yara_rules_list: List[Any] = []
        # Surfaced to the rules catalog like SigmaEngine.load_errors, so a
        # ruleset that partially failed to compile is visible, not silent.
        self.yara_load_errors: List[Dict[str, str]] = []
        self.yara_rule_count: int = 0
        self._load_yara_rules()

    def yara_rule_dirs(self) -> List[Path]:
        """All existing YARA rule directories (vendored first, then custom)."""
        dirs: List[Path] = []
        if self.yara_rules_dir:
            dirs.append(self.yara_rules_dir)
        dirs.extend(self.custom_rules_dirs)
        return _normalize_yara_dirs(dirs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, file_path: str | Path, run_capa: Optional[bool] = None) -> Dict[str, Any]:
        """Run the full static analysis pipeline on a file.

        run_capa overrides the config gate: pass False to skip the capa
        subprocess (used by the dropped-file deep-analysis pass, which runs
        capa selectively itself since one 180s-bounded capa invocation per
        dropped file would otherwise dominate run time).
        """
        path = Path(file_path)
        data = path.read_bytes()

        entropy = self.calculate_entropy(data)
        pe_info = self.parse_pe(path)
        packing = self._assess_packing(entropy, pe_info)

        result: Dict[str, Any] = {
            "file_path": str(path),
            "size": len(data),
            "hashes": self._compute_hashes(data),
            "file_type": self.identify_file_type(data, path),
            "entropy": entropy,
            "packed_suspected": packing["packed_suspected"],
            "packing_reasons": packing["packing_reasons"],
            "pe": pe_info,
            "strings": self.extract_strings(data),
            "yara": self.match_yara(path),
            "signature": self.check_signature(path),
        }

        # capa capability analysis (ATT&CK/MBC). Gated + timeout-bounded in
        # capa_analysis; returns {available: False, reason} for non-PE samples
        # or when rules aren't vendored, so it's always safe to include.
        capa_enabled = self.capa_config.get("enabled") if run_capa is None else run_capa
        if capa_enabled:
            result["capa"] = capa_analysis.analyze_file(path, self.capa_config)

        if self.vt_api_key:
            result["virustotal"] = self.query_virustotal(result["hashes"]["sha256"])

        return result

    # ------------------------------------------------------------------
    # File type
    # ------------------------------------------------------------------

    @staticmethod
    def identify_file_type(data: bytes, path: Path) -> Dict[str, Any]:
        """Identify file type using libmagic-style detection."""
        kind = filetype.guess(data)
        if kind:
            return {
                "extension": kind.extension,
                "mime": kind.mime,
                "name": getattr(kind, "name", kind.mime.split("/")[-1]),
            }
        # Fallback: common Windows extensions
        ext = path.suffix.lower()
        fallback = {
            ".exe": {"extension": "exe", "mime": "application/x-msdownload", "name": "Windows executable"},
            ".dll": {"extension": "dll", "mime": "application/x-msdownload", "name": "Windows DLL"},
            ".bat": {"extension": "bat", "mime": "text/x-msdos-batch", "name": "DOS batch file"},
            ".ps1": {"extension": "ps1", "mime": "text/x-powershell", "name": "PowerShell script"},
            ".cmd": {"extension": "cmd", "mime": "text/x-msdos-batch", "name": "Windows command script"},
        }
        return fallback.get(ext, {"extension": ext, "mime": "application/octet-stream", "name": "Unknown"})

    # ------------------------------------------------------------------
    # Hashes
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hashes(data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "ssdeep": ppdeep.hash(data),
        }

    @classmethod
    def hash_file(cls, path: Path) -> Dict[str, str]:
        """Public, cheap, hashes-only pass -- used by the executor to populate
        sample metadata up front while the full analyze() runs on a background
        thread (hashes are also how reports get matched to samples)."""
        return cls._compute_hashes(Path(path).read_bytes())

    # ------------------------------------------------------------------
    # Packing / entropy assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _assess_packing(entropy: float, pe_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Flag likely packed/encrypted content using the same entropy
        threshold as yara/suspicious_strings.yar's high_entropy_section rule.
        """
        reasons: List[str] = []
        if entropy > HIGH_ENTROPY_THRESHOLD:
            reasons.append(f"whole-file entropy {entropy} exceeds {HIGH_ENTROPY_THRESHOLD}")

        if pe_info:
            for section in pe_info.get("sections", []):
                is_executable = int(section["characteristics"], 16) & IMAGE_SCN_MEM_EXECUTE != 0
                if is_executable and section["entropy"] > HIGH_ENTROPY_THRESHOLD:
                    reasons.append(
                        f"executable section '{section['name']}' entropy {section['entropy']} exceeds {HIGH_ENTROPY_THRESHOLD}"
                    )

        return {"packed_suspected": bool(reasons), "packing_reasons": reasons}

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Shannon entropy of a byte string (0.0 - 8.0)."""
        if not data:
            return 0.0
        length = len(data)
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    # ------------------------------------------------------------------
    # PE parsing
    # ------------------------------------------------------------------

    def parse_pe(self, path: Path) -> Optional[Dict[str, Any]]:
        """Parse PE headers and metadata if the file is a Windows executable."""
        try:
            pe = pefile.PE(str(path))
        except pefile.PEFormatError:
            return None

        sections = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            sections.append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
                "characteristics": hex(section.Characteristics),
            })

        imports: List[Dict[str, Any]] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                functions = [imp.name.decode("utf-8", errors="ignore") if imp.name else str(imp.ordinal) for imp in entry.imports]
                imports.append({"dll": dll, "functions": functions})

        exports: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"ordinal_{exp.ordinal}"
                exports.append(name)

        result: Dict[str, Any] = {
            "is_pe": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, "OPTIONAL_HEADER") else None,
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe, "OPTIONAL_HEADER") else None,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, "OPTIONAL_HEADER") else None,
            "sections": sections,
            "imports": imports,
            "exports": exports,
        }

        # Rich header
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            result["rich_header"] = {
                "checksum": hex(pe.RICH_HEADER.checksum),
                "values": [hex(v) for v in pe.RICH_HEADER.values],
            }

        # .NET / CLR metadata (data directory 14 = COM descriptor)
        has_clr = (
            hasattr(pe, "OPTIONAL_HEADER")
            and len(getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])) > 14
            and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
        )
        if has_clr:
            result["dotnet"] = self.parse_dotnet(path)

        pe.close()
        return result

    # Known managed-packers/obfuscators, matched case-insensitively against
    # TypeRef/attribute names and user strings. Deliberately short and
    # high-precision -- this is a triage hint, not a classifier.
    _DOTNET_OBFUSCATOR_MARKERS = [
        "confuserex", "confuser.core", "obfuscar", "dotfuscator",
        "smartassembly", "eazfuscator", "babel.obfuscator", "agiledotnet",
        "net reactor", "deepsea", "phoenixprotector", "netshencode",
    ]

    _DOTNET_MAX_TYPEREFS = 200
    _DOTNET_MAX_USER_STRINGS = 100

    @staticmethod
    def parse_dotnet(path: Path) -> Optional[Dict[str, Any]]:
        """Extract .NET/CLR metadata with dnfile (already installed as capa's
        .NET backend). Best-effort per section: a corrupt/obfuscated metadata
        block degrades to whatever parsed, never an exception. Returns None
        when dnfile is unavailable or the file has no managed metadata.
        """
        try:
            import dnfile
        except ImportError:
            return None
        try:
            dn = dnfile.dnPE(str(path))
        except Exception:
            return None
        try:
            net = getattr(dn, "net", None)
            if net is None or getattr(net, "metadata", None) is None:
                return None

            result: Dict[str, Any] = {}
            try:
                struct = net.struct
                flags = int(getattr(struct, "Flags", 0))
                result["runtime_version"] = f"{struct.MajorRuntimeVersion}.{struct.MinorRuntimeVersion}"
                result["entry_point_token"] = hex(getattr(struct, "EntryPointTokenOrRva", 0))
                # COMIMAGE_FLAGS_ILONLY (0x1): unset means native+IL mixed mode
                result["mixed_mode"] = not bool(flags & 0x1)
            except Exception as exc:
                result["header_error"] = str(exc)

            try:
                result["metadata_streams"] = [
                    s.struct.Name.decode("utf-8", errors="ignore")
                    for s in net.metadata.streams_list
                ]
            except Exception:
                result["metadata_streams"] = []

            def _table_names(table, cap):
                names = []
                if table is None or not getattr(table, "rows", None):
                    return names
                for row in table.rows[:cap]:
                    ns = str(getattr(row, "TypeNamespace", "") or "")
                    name = str(getattr(row, "TypeName", "") or "")
                    if name and name != "<Module>":
                        names.append(f"{ns}.{name}" if ns else name)
                return names

            try:
                mdtables = net.mdtables
                result["type_refs"] = _table_names(getattr(mdtables, "TypeRef", None), StaticAnalyzer._DOTNET_MAX_TYPEREFS)
                result["type_defs"] = _table_names(getattr(mdtables, "TypeDef", None), StaticAnalyzer._DOTNET_MAX_TYPEREFS)
                asm = getattr(mdtables, "Assembly", None)
                if asm is not None and getattr(asm, "rows", None):
                    result["assembly_name"] = str(getattr(asm.rows[0], "Name", "") or "")
            except Exception as exc:
                result["tables_error"] = str(exc)

            user_strings: List[str] = []
            try:
                us_heap = net.user_strings
                heap_size = us_heap.sizeof()
                offset = 1  # index 0 is the empty string
                # A valid record needs >= 2 bytes (length prefix + trailing
                # flag); stop before probing the heap tail so dnfile's
                # "string missing trailing flag" warning doesn't fire.
                while offset + 2 <= heap_size and len(user_strings) < StaticAnalyzer._DOTNET_MAX_USER_STRINGS:
                    us = us_heap.get(offset)
                    if us is None:
                        break
                    if us.value:
                        user_strings.append(us.value)
                    item_size = max(int(getattr(us, "item_size", 0) or 0), 1)
                    # heap offsets advance past the compressed-length prefix
                    # (1/2/4 bytes by size) plus the item itself.
                    prefix = 1 if item_size < 0x80 else (2 if item_size < 0x4000 else 4)
                    offset += prefix + item_size
                result["user_strings"] = user_strings
            except Exception as exc:
                result["user_strings_error"] = str(exc)

            haystack = "\n".join(
                result.get("type_refs", []) + result.get("type_defs", []) + user_strings
            ).lower()
            hits = [m for m in StaticAnalyzer._DOTNET_OBFUSCATOR_MARKERS if m in haystack]
            result["obfuscator_suspected"] = bool(hits)
            result["obfuscator_markers"] = hits
            return result
        finally:
            dn.close()  # pefile API; safe even if partially parsed

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    @staticmethod
    def extract_strings(
        data: bytes,
        min_length: int = 4,
        max_strings: int = 1000,
    ) -> Dict[str, List[str]]:
        """Extract ASCII and Unicode strings."""
        ascii_re = rb"[\x20-\x7E]{%d,}" % min_length
        unicode_re = rb"(?:[\x20-\x7E]\x00){%d,}" % min_length

        ascii_strings = re.findall(ascii_re, data)[:max_strings]
        unicode_raw = re.findall(unicode_re, data)[:max_strings]
        unicode_strings = [s.decode("utf-16le", errors="ignore") for s in unicode_raw]

        # Decode bytes to str
        ascii_strings = [s.decode("ascii", errors="ignore") for s in ascii_strings]

        return {
            "ascii": ascii_strings,
            "unicode": unicode_strings,
            "interesting": StaticAnalyzer._interesting_strings(ascii_strings + unicode_strings),
        }

    @staticmethod
    def _interesting_strings(strings: List[str]) -> List[str]:
        """Filter strings that look like URLs, IPs, paths, or commands."""
        patterns = [
            re.compile(r"https?://[^\s\"]+", re.IGNORECASE),
            re.compile(r"[A-Za-z]:\\[^\s\"]+"),
            re.compile(r"\\(?:[\w\-]+\\)+[\w\-]+\.\w+"),
            re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            re.compile(r"powershell|cmd\.exe|rundll32|regsvr32|mshta|certutil", re.IGNORECASE),
        ]
        interesting = set()
        for s in strings:
            for pattern in patterns:
                if pattern.search(s):
                    interesting.add(s)
                    break
        return sorted(interesting)[:200]

    # ------------------------------------------------------------------
    # YARA
    # ------------------------------------------------------------------

    @staticmethod
    def _count_yara_rules(compiled: Any) -> int:
        """Count rules in a compiled yara.Rules object (iterable in
        yara-python 4.x). Falls back to 0 if the build doesn't support it."""
        try:
            return sum(1 for _ in compiled)
        except TypeError:
            return 0

    def _yara_namespaces(self) -> Dict[str, str]:
        """namespace -> filepath for every rule file across all dirs. The
        namespace is the file path relative to its parent, which keeps
        per-file compile errors and match namespaces human-readable and unique
        across the vendored + custom trees."""
        namespaces: Dict[str, str] = {}
        for base, path in _iter_yara_files(self.yara_rule_dirs()):
            try:
                rel = path.relative_to(base.parent).as_posix()
            except ValueError:
                rel = path.name
            # Disambiguate the rare collision of identical relative paths from
            # two different bases.
            key = rel
            suffix = 1
            while key in namespaces and namespaces[key] != str(path):
                suffix += 1
                key = f"{rel}#{suffix}"
            namespaces[key] = str(path)
        return namespaces

    def _load_yara_rules(self) -> None:
        """Compile the ruleset with graceful degradation.

        Fast path: compile every file together into one Rules object. If that
        fails (one bad rule in a large vendored set would otherwise take the
        whole set down -- the previous behavior silently set rules to None and
        disabled ALL YARA), fall back to per-file isolation: compile each file
        on its own, keep the ones that compile, and record the failures in
        yara_load_errors so the gap is visible in the rules catalog.
        """
        self._yara_rules = None
        self._yara_rules_list = []
        self.yara_load_errors = []
        self.yara_rule_count = 0

        namespaces = self._yara_namespaces()
        if not namespaces:
            return

        try:
            import yara
        except Exception as exc:  # pragma: no cover - yara-python always present in this project
            self.yara_load_errors.append({"scope": "import", "error": str(exc)})
            return

        # Fast path: one combined compile.
        try:
            self._yara_rules = yara.compile(filepaths=namespaces, externals=_YARA_EXTERNALS)
            self.yara_rule_count = self._count_yara_rules(self._yara_rules)
            return
        except yara.Error as exc:
            self.yara_load_errors.append({"scope": "combined-compile", "error": str(exc)})
            self._yara_rules = None

        # Fallback: per-file isolation so one uncompilable file (or the rules
        # it contains) can't disable the rest of the set.
        compiled: List[Any] = []
        count = 0
        for namespace, filepath in namespaces.items():
            try:
                rules = yara.compile(filepaths={namespace: filepath}, externals=_YARA_EXTERNALS)
            except yara.Error as exc:
                self.yara_load_errors.append({"scope": namespace, "error": str(exc)})
                continue
            compiled.append(rules)
            count += self._count_yara_rules(rules)
        self._yara_rules_list = compiled
        self.yara_rule_count = count

    def match_yara(self, path: Path) -> List[Dict[str, Any]]:
        """Match the compiled YARA ruleset against a file. Handles both the
        fast-path single Rules object and the per-file fallback list, and
        supplies the per-file external variables (filename/extension/...) that
        on-disk-scan rules gate on."""
        path = Path(path)
        externals = dict(_YARA_EXTERNALS)
        externals.update(
            {
                "filename": path.name,
                "filepath": str(path),
                "extension": path.suffix.lstrip(".").lower(),
            }
        )

        matches: List[Any] = []
        try:
            if self._yara_rules is not None:
                matches = list(self._yara_rules.match(str(path), externals=externals))
            elif self._yara_rules_list:
                for rules in self._yara_rules_list:
                    matches.extend(rules.match(str(path), externals=externals))
        except Exception:
            return []

        results = []
        for match in matches:
            strings = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    strings.append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "data": instance.matched_data.decode("latin-1", errors="replace"),
                    })
            results.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "strings": strings,
            })
        return results

    # ------------------------------------------------------------------
    # Signature
    # ------------------------------------------------------------------

    @staticmethod
    def check_signature(path: Path) -> Dict[str, Any]:
        """Check Authenticode signature using PowerShell Get-AuthenticodeSignature."""
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-ExecutionPolicy", "Bypass",
                    "-Command",
                    f"(Get-AuthenticodeSignature '{path}').Status | Out-String -Stream",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            status = proc.stdout.strip()
        except Exception as exc:
            status = f"error: {exc}"

        return {
            "status": status,
            "signed": status == "Valid",
        }

    # ------------------------------------------------------------------
    # VirusTotal (optional)
    # ------------------------------------------------------------------

    def query_virustotal(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for a SHA256 hash."""
        if not self.vt_api_key:
            return None

        try:
            import requests
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "found": True,
                    "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "undetected": attrs.get("last_analysis_stats", {}).get("undetected", 0),
                    "names": attrs.get("names", [])[:10],
                    "link": f"https://www.virustotal.com/gui/file/{sha256}",
                }
            if resp.status_code == 404:
                return {"found": False}
            return {"found": False, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"found": False, "error": str(exc)}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: static_analysis.py <file> [yara_rules_dir]")
        sys.exit(1)

    yara_dir = sys.argv[2] if len(sys.argv) > 2 else "yara"
    analyzer = StaticAnalyzer(yara_rules_dir=yara_dir)
    result = analyzer.analyze(sys.argv[1])
    print(__import__("json").dumps(result, indent=2, default=str))
