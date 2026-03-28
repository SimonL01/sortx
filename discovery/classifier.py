from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable

try:
    import magic  # type: ignore
except ImportError:  # pragma: no cover - optional enrichment only
    magic = None


HEADER_READ_BYTES = 4096
HEADER_HEX_BYTES = 32


@dataclass(frozen=True, slots=True)
class FileClassification:
    tag: str
    family: str
    description: str
    method: str
    confidence: float
    rule_name: str
    extension: str
    file_name: str
    header_hex: str
    mime_type: str | None = None
    magic_description: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "tag": self.tag,
            "family": self.family,
            "description": self.description,
            "method": self.method,
            "confidence": round(self.confidence, 3),
            "rule_name": self.rule_name,
            "extension": self.extension,
            "file_name": self.file_name,
            "header_hex": self.header_hex,
            "mime_type": self.mime_type,
            "magic_description": self.magic_description,
        }


@dataclass(frozen=True, slots=True)
class SignatureRule:
    name: str
    tag: str
    family: str
    description: str
    mime_type: str | None
    confidence: float

    def matches(self, header: bytes) -> bool:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class OffsetSignatureRule(SignatureRule):
    offset: int
    pattern: bytes

    def matches(self, header: bytes) -> bool:
        end = self.offset + len(self.pattern)
        return len(header) >= end and header[self.offset:end] == self.pattern


@dataclass(frozen=True, slots=True)
class PredicateRule(SignatureRule):
    predicate: Callable[[bytes], bool]

    def matches(self, header: bytes) -> bool:
        return bool(self.predicate(header))


STRICT_FILENAME_RULES: tuple[tuple[str, str, str, str, str, float], ...] = (
    ("$mft", "ntfs-mft", "ntfs-metadata", "NTFS Master File Table", "forensic_filename", 1.0),
    ("$mftmirr", "ntfs-mftmirr", "ntfs-metadata", "NTFS MFT mirror", "forensic_filename", 1.0),
    ("$logfile", "ntfs-logfile", "ntfs-metadata", "NTFS transaction log", "forensic_filename", 1.0),
    ("$bitmap", "ntfs-bitmap", "ntfs-metadata", "NTFS allocation bitmap", "forensic_filename", 1.0),
    ("$secure", "ntfs-secure", "ntfs-metadata", "NTFS security descriptor stream", "forensic_filename", 1.0),
    ("$boot", "ntfs-boot", "ntfs-metadata", "NTFS boot sector", "forensic_filename", 1.0),
    ("$usnjrnl", "ntfs-usnjrnl", "ntfs-metadata", "NTFS Update Sequence Number journal", "forensic_filename", 1.0),
    ("$j", "ntfs-usnjrnl", "ntfs-metadata", "NTFS Update Sequence Number journal stream", "forensic_filename", 0.95),
    ("pagefile.sys", "pagefile", "memory", "Windows pagefile", "forensic_filename", 0.95),
)

ADVISORY_FILENAME_RULES: tuple[tuple[str, str, str, str, str, float], ...] = (
    ("sam", "registry-hive", "registry", "Windows SAM registry hive", "forensic_filename", 1.0),
    ("security", "registry-hive", "registry", "Windows SECURITY registry hive", "forensic_filename", 1.0),
    ("software", "registry-hive", "registry", "Windows SOFTWARE registry hive", "forensic_filename", 1.0),
    ("system", "registry-hive", "registry", "Windows SYSTEM registry hive", "forensic_filename", 1.0),
    ("default", "registry-hive", "registry", "Windows DEFAULT registry hive", "forensic_filename", 1.0),
    ("components", "registry-hive", "registry", "Windows COMPONENTS registry hive", "forensic_filename", 1.0),
    ("amcache.hve", "registry-hive", "registry", "Amcache registry hive", "forensic_filename", 1.0),
    ("bcd", "registry-hive", "registry", "Boot Configuration Data hive", "forensic_filename", 1.0),
    ("ntuser.dat", "registry-hive", "registry", "User NTUSER.DAT registry hive", "forensic_filename", 1.0),
    ("usrclass.dat", "registry-hive", "registry", "User UsrClass.dat registry hive", "forensic_filename", 1.0),
    ("hiberfil.sys", "hibernation-file", "memory", "Windows hibernation file", "forensic_filename", 0.95),
)

REGISTRY_LOG_NAME = re.compile(
    r"^(sam|security|software|system|default|components|amcache\.hve|bcd|ntuser\.dat|usrclass\.dat)"
    r"(\.log|\.log1|\.log2|\.blf|\.regtrans-ms)$",
    re.IGNORECASE,
)

JUMPLIST_SUFFIXES: tuple[tuple[str, str, str], ...] = (
    (".automaticdestinations-ms", "jumplist-automaticdestinations", "AutomaticDestinations Jump List"),
    (".customdestinations-ms", "jumplist-customdestinations", "CustomDestinations Jump List"),
)

EXTENSION_RULES: tuple[tuple[tuple[str, ...], str, str, str, str, float], ...] = (
    ((".evtx",), "evtx", "windows-eventing", "Windows Event Log", "extension", 0.7),
    ((".etl",), "etl", "windows-eventing", "Event Trace Log", "extension", 0.75),
    ((".pf",), "prefetch", "windows-execution", "Windows Prefetch file", "extension", 0.7),
    ((".lnk",), "lnk", "windows-shell", "Windows shortcut", "extension", 0.75),
    ((".xml",), "xml", "structured-text", "XML document", "extension", 0.7),
    ((".ipynb",), "jupyter-notebook", "notebook", "Jupyter notebook", "extension", 0.85),
    ((".json",), "json", "structured-text", "JSON document", "extension", 0.7),
    ((".pcap",), "pcap", "network-capture", "Packet capture", "extension", 0.75),
    ((".pcapng",), "pcapng", "network-capture", "Packet capture", "extension", 0.75),
    ((".yml", ".yaml"), "yaml", "structured-text", "YAML document", "extension", 0.8),
    ((".csv",), "csv", "text", "CSV text file", "extension", 0.7),
    ((".md", ".markdown"), "markdown", "documentation", "Markdown document", "extension", 0.8),
    ((".html", ".htm"), "html", "web", "HTML document", "extension", 0.8),
    ((".ps1", ".psm1", ".psd1"), "powershell", "script", "PowerShell script", "extension", 0.85),
    ((".py", ".pyw"), "python", "script", "Python source", "extension", 0.85),
    ((".pyc", ".pyo"), "python-bytecode", "script", "Python bytecode", "extension", 0.85),
    ((".sh", ".bash", ".zsh"), "shell-script", "script", "Shell script", "extension", 0.85),
    ((".js", ".mjs", ".cjs"), "javascript", "script", "JavaScript source", "extension", 0.8),
    ((".css",), "css", "web", "CSS stylesheet", "extension", 0.8),
    ((".toml",), "toml", "structured-text", "TOML document", "extension", 0.8),
    ((".ini", ".cfg", ".conf", ".config"), "config", "structured-text", "Configuration file", "extension", 0.75),
    ((".log",), "log", "log", "Log file", "extension", 0.75),
    ((".txt",), "text", "text", "Plain text file", "extension", 0.65),
)

SIGNATURE_RULES: tuple[SignatureRule, ...] = (
    OffsetSignatureRule(
        name="evtx-header",
        tag="evtx",
        family="windows-eventing",
        description="Windows Event Log",
        mime_type=None,
        confidence=1.0,
        offset=0,
        pattern=b"ElfFile\x00",
    ),
    OffsetSignatureRule(
        name="registry-regf",
        tag="registry-hive",
        family="registry",
        description="Windows registry hive",
        mime_type=None,
        confidence=1.0,
        offset=0,
        pattern=b"regf",
    ),
    OffsetSignatureRule(
        name="lnk-shell-link-header",
        tag="lnk",
        family="windows-shell",
        description="Windows shortcut",
        mime_type=None,
        confidence=0.98,
        offset=0,
        pattern=b"\x4c\x00\x00\x00\x01\x14\x02\x00",
    ),
    OffsetSignatureRule(
        name="pcap-little-endian-microsecond",
        tag="pcap",
        family="network-capture",
        description="Packet capture",
        mime_type="application/vnd.tcpdump.pcap",
        confidence=1.0,
        offset=0,
        pattern=b"\xd4\xc3\xb2\xa1",
    ),
    OffsetSignatureRule(
        name="pcap-big-endian-microsecond",
        tag="pcap",
        family="network-capture",
        description="Packet capture",
        mime_type="application/vnd.tcpdump.pcap",
        confidence=1.0,
        offset=0,
        pattern=b"\xa1\xb2\xc3\xd4",
    ),
    OffsetSignatureRule(
        name="pcap-little-endian-nanosecond",
        tag="pcap",
        family="network-capture",
        description="Packet capture",
        mime_type="application/vnd.tcpdump.pcap",
        confidence=1.0,
        offset=0,
        pattern=b"\x4d\x3c\xb2\xa1",
    ),
    OffsetSignatureRule(
        name="pcap-big-endian-nanosecond",
        tag="pcap",
        family="network-capture",
        description="Packet capture",
        mime_type="application/vnd.tcpdump.pcap",
        confidence=1.0,
        offset=0,
        pattern=b"\xa1\xb2\x3c\x4d",
    ),
    OffsetSignatureRule(
        name="pcapng-header",
        tag="pcapng",
        family="network-capture",
        description="Packet capture",
        mime_type="application/x-pcapng",
        confidence=1.0,
        offset=0,
        pattern=b"\x0a\x0d\x0d\x0a",
    ),
    OffsetSignatureRule(
        name="zip-local-file-header",
        tag="zip",
        family="archive",
        description="ZIP archive",
        mime_type="application/zip",
        confidence=0.98,
        offset=0,
        pattern=b"PK\x03\x04",
    ),
    OffsetSignatureRule(
        name="zip-empty-archive",
        tag="zip",
        family="archive",
        description="ZIP archive",
        mime_type="application/zip",
        confidence=0.98,
        offset=0,
        pattern=b"PK\x05\x06",
    ),
    OffsetSignatureRule(
        name="zip-spanned-archive",
        tag="zip",
        family="archive",
        description="ZIP archive",
        mime_type="application/zip",
        confidence=0.98,
        offset=0,
        pattern=b"PK\x07\x08",
    ),
    OffsetSignatureRule(
        name="ole-compound-file",
        tag="olecf",
        family="compound-document",
        description="OLE Compound File",
        mime_type="application/x-ole-storage",
        confidence=0.98,
        offset=0,
        pattern=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ),
    OffsetSignatureRule(
        name="sqlite3-header",
        tag="sqlite",
        family="database",
        description="SQLite database",
        mime_type="application/vnd.sqlite3",
        confidence=1.0,
        offset=0,
        pattern=b"SQLite format 3\x00",
    ),
    OffsetSignatureRule(
        name="pdf-header",
        tag="pdf",
        family="document",
        description="PDF document",
        mime_type="application/pdf",
        confidence=1.0,
        offset=0,
        pattern=b"%PDF-",
    ),
    OffsetSignatureRule(
        name="png-header",
        tag="png",
        family="image",
        description="PNG image",
        mime_type="image/png",
        confidence=1.0,
        offset=0,
        pattern=b"\x89PNG\r\n\x1a\n",
    ),
    OffsetSignatureRule(
        name="jpeg-header",
        tag="jpeg",
        family="image",
        description="JPEG image",
        mime_type="image/jpeg",
        confidence=0.98,
        offset=0,
        pattern=b"\xff\xd8\xff",
    ),
    OffsetSignatureRule(
        name="gif87a-header",
        tag="gif",
        family="image",
        description="GIF image",
        mime_type="image/gif",
        confidence=1.0,
        offset=0,
        pattern=b"GIF87a",
    ),
    OffsetSignatureRule(
        name="gif89a-header",
        tag="gif",
        family="image",
        description="GIF image",
        mime_type="image/gif",
        confidence=1.0,
        offset=0,
        pattern=b"GIF89a",
    ),
    OffsetSignatureRule(
        name="gzip-header",
        tag="gzip",
        family="archive",
        description="Gzip archive",
        mime_type="application/gzip",
        confidence=1.0,
        offset=0,
        pattern=b"\x1f\x8b\x08",
    ),
    OffsetSignatureRule(
        name="seven-zip-header",
        tag="7z",
        family="archive",
        description="7-Zip archive",
        mime_type="application/x-7z-compressed",
        confidence=1.0,
        offset=0,
        pattern=b"7z\xbc\xaf'\x1c",
    ),
    OffsetSignatureRule(
        name="rar-v4-header",
        tag="rar",
        family="archive",
        description="RAR archive",
        mime_type="application/vnd.rar",
        confidence=1.0,
        offset=0,
        pattern=b"Rar!\x1a\x07\x00",
    ),
    OffsetSignatureRule(
        name="rar-v5-header",
        tag="rar",
        family="archive",
        description="RAR archive",
        mime_type="application/vnd.rar",
        confidence=1.0,
        offset=0,
        pattern=b"Rar!\x1a\x07\x01\x00",
    ),
    PredicateRule(
        name="portable-executable",
        tag="pe",
        family="executable",
        description="Portable Executable",
        mime_type="application/vnd.microsoft.portable-executable",
        confidence=0.98,
        predicate=lambda header: _matches_pe(header),
    ),
    PredicateRule(
        name="elf-executable",
        tag="elf",
        family="executable",
        description="ELF executable",
        mime_type="application/x-elf",
        confidence=1.0,
        predicate=lambda header: header.startswith(b"\x7fELF"),
    ),
    PredicateRule(
        name="windows-prefetch",
        tag="prefetch",
        family="windows-execution",
        description="Windows Prefetch file",
        mime_type=None,
        confidence=0.95,
        predicate=lambda header: len(header) >= 8 and header[4:8] == b"SCCA",
    ),
    PredicateRule(
        name="hibernation-header",
        tag="hibernation-file",
        family="memory",
        description="Windows hibernation file",
        mime_type=None,
        confidence=0.98,
        predicate=lambda header: header.startswith(b"HIBR"),
    ),
)


_magic_description_handle = None
_magic_mime_handle = None
_magic_unavailable = False


def _read_header(file_path: Path, size: int = HEADER_READ_BYTES) -> bytes:
    with file_path.open("rb") as handle:
        return handle.read(size)


def _header_hex(header: bytes) -> str:
    return header[:HEADER_HEX_BYTES].hex()


def _decode_text_prefix(header: bytes) -> str | None:
    if not header:
        return ""

    candidates = ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1")
    for encoding in candidates:
        try:
            text = header.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text_string(text):
            return text
    return None


def _looks_like_text_bytes(header: bytes) -> bool:
    if not header:
        return True

    sample = header[:512]
    if b"\x00" in sample.replace(b"\x00\r\x00\n", b"").replace(b"\x00\n", b""):
        return False

    printable = 0
    for byte in sample:
        if byte in {9, 10, 13} or 32 <= byte <= 126:
            printable += 1
    return printable / len(sample) >= 0.85


def _looks_like_text_string(text: str) -> bool:
    if not text:
        return True

    sample = text[:512]
    printable = 0
    for char in sample:
        if char.isprintable() or char in "\r\n\t":
            printable += 1
    return printable / len(sample) >= 0.85


def _looks_like_csv(text: str) -> bool:
    non_empty_lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(non_empty_lines) < 3:
        return False

    sample_lines = non_empty_lines[:10]
    for delimiter in (",", ";", "\t"):
        counts = [line.count(delimiter) for line in sample_lines]
        populated = [count for count in counts if count > 0]
        if len(populated) < 3:
            continue
        if len(populated) / len(sample_lines) < 0.8:
            continue
        if min(populated) < 1:
            continue
        if max(populated) - min(populated) > 1:
            continue
        return True
    return False


def _matches_pe(header: bytes) -> bool:
    if len(header) < 64 or not header.startswith(b"MZ"):
        return False
    pe_offset = int.from_bytes(header[60:64], "little")
    if pe_offset < 64 or pe_offset + 4 > len(header):
        return False
    return header[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _classify_by_filename(file_path: Path, header_hex: str) -> FileClassification | None:
    name = file_path.name.lower()

    if REGISTRY_LOG_NAME.match(name):
        return FileClassification(
            tag="registry-log",
            family="registry",
            description="Windows registry transaction log",
            method="forensic_filename",
            confidence=0.98,
            rule_name="registry-log-name",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
        )

    for suffix, tag, description in JUMPLIST_SUFFIXES:
        if name.endswith(suffix):
            return FileClassification(
                tag=tag,
                family="windows-shell",
                description=description,
                method="forensic_filename",
                confidence=0.98,
                rule_name=f"suffix:{suffix}",
                extension=file_path.suffix.lower(),
                file_name=file_path.name,
                header_hex=header_hex,
            )

    for candidate, tag, family, description, method, confidence in STRICT_FILENAME_RULES:
        if name == candidate:
            return FileClassification(
                tag=tag,
                family=family,
                description=description,
                method=method,
                confidence=confidence,
                rule_name=f"name:{candidate}",
                extension=file_path.suffix.lower(),
                file_name=file_path.name,
                header_hex=header_hex,
            )

    return None


def _classify_by_advisory_filename(file_path: Path, header_hex: str) -> FileClassification | None:
    name = file_path.name.lower()
    for candidate, tag, family, description, method, confidence in ADVISORY_FILENAME_RULES:
        if name == candidate:
            return FileClassification(
                tag=tag,
                family=family,
                description=description,
                method=method,
                confidence=confidence,
                rule_name=f"name:{candidate}",
                extension=file_path.suffix.lower(),
                file_name=file_path.name,
                header_hex=header_hex,
            )
    return None


def _classify_by_signature(file_path: Path, header: bytes, header_hex: str) -> FileClassification | None:
    for rule in SIGNATURE_RULES:
        if not rule.matches(header):
            continue
        return FileClassification(
            tag=rule.tag,
            family=rule.family,
            description=rule.description,
            method="signature",
            confidence=rule.confidence,
            rule_name=rule.name,
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
            mime_type=rule.mime_type,
        )
    return None


def _classify_text(file_path: Path, header: bytes, header_hex: str) -> FileClassification | None:
    text = _decode_text_prefix(header)
    if text is None:
        return None

    stripped = text.lstrip()
    lowered = stripped.lower()
    if stripped.startswith("<?xml"):
        return FileClassification(
            tag="xml",
            family="structured-text",
            description="XML document",
            method="text",
            confidence=0.9,
            rule_name="text:xml-declaration",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
            mime_type="text/xml",
        )
    if stripped.startswith("{") or stripped.startswith("["):
        return FileClassification(
            tag="json",
            family="structured-text",
            description="JSON document",
            method="text",
            confidence=0.88,
            rule_name="text:json-leading-token",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
            mime_type="application/json",
        )
    if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        return FileClassification(
            tag="html",
            family="web",
            description="HTML document",
            method="text",
            confidence=0.86,
            rule_name="text:html-markup",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
            mime_type="text/html",
        )
    if _looks_like_csv(text):
        return FileClassification(
            tag="csv",
            family="text",
            description="Delimited text file",
            method="text",
            confidence=0.72,
            rule_name="text:csv-heuristic",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
            mime_type="text/csv",
        )
    return FileClassification(
        tag="text",
        family="text",
        description="Plain text file",
        method="text",
        confidence=0.7,
        rule_name="text:printable-content",
        extension=file_path.suffix.lower(),
        file_name=file_path.name,
        header_hex=header_hex,
        mime_type="text/plain",
    )


def _classify_by_extension(file_path: Path, header_hex: str) -> FileClassification | None:
    extension = file_path.suffix.lower()
    for extensions, tag, family, description, method, confidence in EXTENSION_RULES:
        if extension in extensions:
            return FileClassification(
                tag=tag,
                family=family,
                description=description,
                method=method,
                confidence=confidence,
                rule_name=f"extension:{extension}",
                extension=extension,
                file_name=file_path.name,
                header_hex=header_hex,
            )
    return None


def _classify_unknown(file_path: Path, header_hex: str) -> FileClassification:
    return FileClassification(
        tag="unknown",
        family="unknown",
        description="Unknown binary or unsupported format",
        method="unknown",
        confidence=0.0,
        rule_name="unknown",
        extension=file_path.suffix.lower(),
        file_name=file_path.name,
        header_hex=header_hex,
    )


def _probe_magic(file_path: Path) -> tuple[str | None, str | None]:
    global _magic_description_handle, _magic_mime_handle, _magic_unavailable
    if magic is None or _magic_unavailable:
        return None, None

    try:
        if _magic_description_handle is None:
            _magic_description_handle = magic.Magic()
        if _magic_mime_handle is None:
            _magic_mime_handle = magic.Magic(mime=True)
        resolved = str(file_path.resolve())
        return (
            _magic_description_handle.from_file(resolved),
            _magic_mime_handle.from_file(resolved),
        )
    except Exception:
        _magic_unavailable = True
        return None, None


def classify_file(file_path: Path) -> FileClassification:
    header = _read_header(file_path)
    header_hex = _header_hex(header)

    if not header:
        classification = FileClassification(
            tag="empty",
            family="empty",
            description="Empty file",
            method="size",
            confidence=1.0,
            rule_name="empty-file",
            extension=file_path.suffix.lower(),
            file_name=file_path.name,
            header_hex=header_hex,
        )
    else:
        classification = (
            _classify_by_filename(file_path, header_hex)
            or _classify_by_signature(file_path, header, header_hex)
            or _classify_by_advisory_filename(file_path, header_hex)
            or _classify_by_extension(file_path, header_hex)
            or _classify_text(file_path, header, header_hex)
            or _classify_unknown(file_path, header_hex)
        )

    magic_description, magic_mime = _probe_magic(file_path)
    if classification.mime_type is None and magic_mime:
        classification = FileClassification(
            tag=classification.tag,
            family=classification.family,
            description=classification.description,
            method=classification.method,
            confidence=classification.confidence,
            rule_name=classification.rule_name,
            extension=classification.extension,
            file_name=classification.file_name,
            header_hex=classification.header_hex,
            mime_type=magic_mime,
            magic_description=magic_description,
        )
    elif magic_description:
        classification = FileClassification(
            tag=classification.tag,
            family=classification.family,
            description=classification.description,
            method=classification.method,
            confidence=classification.confidence,
            rule_name=classification.rule_name,
            extension=classification.extension,
            file_name=classification.file_name,
            header_hex=classification.header_hex,
            mime_type=classification.mime_type,
            magic_description=magic_description,
        )

    return classification


def describe_file(file_path: Path) -> str:
    return classify_file(file_path).description


def classify_description(file_description: str) -> str:
    normalized = file_description.strip().lower()
    mapping = {
        "windows event log": "evtx",
        "windows registry hive": "registry-hive",
        "windows shortcut": "lnk",
        "zip archive": "zip",
        "pdf document": "pdf",
        "png image": "png",
        "jpeg image": "jpeg",
        "xml document": "xml",
        "json document": "json",
        "jupyter notebook": "jupyter-notebook",
        "yaml document": "yaml",
        "markdown document": "markdown",
        "html document": "html",
        "powershell script": "powershell",
        "python source": "python",
        "python bytecode": "python-bytecode",
        "packet capture": "pcap",
        "event trace log": "etl",
        "log file": "log",
        "plain text file": "text",
        "sqlite database": "sqlite",
        "portable executable": "pe",
        "ole compound file": "olecf",
    }
    return mapping.get(normalized, "unknown")
