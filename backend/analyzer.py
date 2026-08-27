"""
analyzer.py — Static PE feature extraction for ScanForge.

Uses pefile to inspect the binary byte-level. The file's code is NEVER
mapped into an executable segment, run under any interpreter, VM, or
emulator. This is 100% read-only structural inspection.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import Any, Dict, List, Optional

import pefile


# ── Known suspicious APIs (must match scorer.py) ──────────────────────────────
SUSPICIOUS_API_NAMES = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
    "OpenProcess", "ReadProcessMemory", "LoadLibraryA", "GetProcAddress",
    "IsDebuggerPresent", "ZwQueryInformationProcess",
}


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (bits per byte, 0–8 range)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_features(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parse a PE file from raw bytes and return a flat feature dictionary.

    Never writes to disk, never spawns a process, never maps executable pages.

    Parameters
    ----------
    raw_bytes : bytes
        The complete file content.

    Returns
    -------
    dict with keys:
        sha256, file_size, num_sections, avg_section_entropy,
        max_section_entropy, num_imports, suspicious_api_count,
        suspicious_apis_found, ep_outside_text, no_import_table,
        parse_error (str | None)
    """
    features: Dict[str, Any] = {
        "sha256":               hashlib.sha256(raw_bytes).hexdigest(),
        "file_size":            len(raw_bytes),
        "num_sections":         0,
        "avg_section_entropy":  0.0,
        "max_section_entropy":  0.0,
        "num_imports":          0,
        "suspicious_api_count": 0,
        "suspicious_apis_found": [],
        "ep_outside_text":      False,
        "no_import_table":      True,
        "parse_error":          None,
    }

    try:
        pe = pefile.PE(data=raw_bytes, fast_load=False)
    except pefile.PEFormatError as exc:
        features["parse_error"] = f"PE parse error: {exc}"
        features["raw_byte_entropy"] = round(_shannon_entropy(raw_bytes), 4)
        return features
    except Exception as exc:  # noqa: BLE001
        features["parse_error"] = f"Unexpected error during parsing: {exc}"
        features["raw_byte_entropy"] = round(_shannon_entropy(raw_bytes), 4)
        return features

    # ── Sections & entropy ────────────────────────────────────────────────────
    section_entropies: List[float] = []
    text_section_va_range: Optional[tuple] = None  # (start_va, end_va)

    for section in pe.sections:
        data = section.get_data()
        ent = _shannon_entropy(data)
        section_entropies.append(ent)

        # Identify the .text section to validate entry point location
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").lower()
        if name in (".text", "code", ".code"):
            va_start = section.VirtualAddress
            va_end   = va_start + section.Misc_VirtualSize
            text_section_va_range = (va_start, va_end)

    features["num_sections"] = len(section_entropies)
    if section_entropies:
        features["avg_section_entropy"] = round(
            sum(section_entropies) / len(section_entropies), 4
        )
        features["max_section_entropy"] = round(max(section_entropies), 4)

    # ── Entry point ───────────────────────────────────────────────────────────
    try:
        ep_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if text_section_va_range:
            va_start, va_end = text_section_va_range
            features["ep_outside_text"] = not (va_start <= ep_va < va_end)
        else:
            # No identifiable .text section — EP is inherently outside a standard layout
            features["ep_outside_text"] = True
    except AttributeError:
        features["ep_outside_text"] = False

    # ── Import table ──────────────────────────────────────────────────────────
    has_imports = False
    all_imports: List[str] = []
    found_suspicious: List[str] = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        has_imports = True
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        name_str = imp.name.decode("ascii", errors="replace")
                    except Exception:  # noqa: BLE001
                        name_str = str(imp.name)
                    all_imports.append(name_str)
                    if name_str in SUSPICIOUS_API_NAMES:
                        if name_str not in found_suspicious:
                            found_suspicious.append(name_str)

    features["no_import_table"]      = not has_imports
    features["num_imports"]          = len(all_imports)
    features["suspicious_api_count"] = len(found_suspicious)
    features["suspicious_apis_found"] = found_suspicious

    pe.close()
    return features
