"""
generate_samples.py — Build three synthetic-but-structurally-valid PE files.

These are NOT malware. They are hand-constructed binary stubs that exhibit
specific structural traits so the ScanForge demo is repeatable and controllable.
No live/weaponised code is present. The binaries are never executed by the system.

Run once at container build time:
    python samples/generate_samples.py
"""

from __future__ import annotations

import os
import struct
import random
import math

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Constants ──────────────────────────────────────────────────────────────────
FILE_ALIGN    = 0x200
SECTION_ALIGN = 0x1000
IMAGE_BASE    = 0x400000


def align_to(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


# ── Byte helpers ───────────────────────────────────────────────────────────────

def w16(v: int) -> bytes: return struct.pack("<H", v & 0xFFFF)
def w32(v: int) -> bytes: return struct.pack("<I", v & 0xFFFFFFFF)


def high_entropy_bytes(size: int, seed: int = 42) -> bytes:
    """Pseudo-random bytes with entropy ≈ 7.9 bits/byte."""
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def low_entropy_bytes(size: int) -> bytes:
    """Typical stub-like bytes: mostly NOP/RET pattern, low entropy."""
    pattern = bytes([0x55, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x31, 0xC0, 0xC3])
    raw = (pattern * (size // len(pattern) + 1))[:size]
    return raw


# ── DOS stub (exactly 64 bytes) ────────────────────────────────────────────────
# Fields: https://wiki.osdev.org/MZ
# Byte offsets (all LE 16-bit unless noted):
#  0  MZ magic
#  2  e_cblp   (bytes on last page)
#  4  e_cp     (page count)
#  6  e_crlc   (relocation count)
#  8  e_cparhdr (header size in paragraphs)
# 10  e_minalloc
# 12  e_maxalloc
# 14  e_ss
# 16  e_sp
# 18  e_csum
# 20  e_ip
# 22  e_cs
# 24  e_lfarlc (file addr of reloc table)
# 26  e_ovno
# 28  e_res[4×2]
# 36  e_oemid
# 38  e_oeminfo
# 40  e_res2[10×2]
# 60  e_lfanew (LE32) ← offset of PE signature

def dos_header(pe_offset: int) -> bytes:
    """Return a minimal but valid 64-byte MZ DOS header."""
    hdr = bytearray(64)
    hdr[0:2]   = b"MZ"
    hdr[2:4]   = w16(0x90)           # e_cblp
    hdr[4:6]   = w16(0x03)           # e_cp
    hdr[6:8]   = w16(0x00)           # e_crlc
    hdr[8:10]  = w16(0x04)           # e_cparhdr
    hdr[10:12] = w16(0x00)           # e_minalloc
    hdr[12:14] = w16(0xFFFF)         # e_maxalloc
    hdr[14:16] = w16(0x00)           # e_ss
    hdr[16:18] = w16(0xB8)           # e_sp
    hdr[18:20] = w16(0x00)           # e_csum
    hdr[20:22] = w16(0x00)           # e_ip
    hdr[22:24] = w16(0x00)           # e_cs
    hdr[24:26] = w16(0x40)           # e_lfarlc
    hdr[26:28] = w16(0x00)           # e_ovno
    # e_res, e_oemid, e_oeminfo, e_res2 → all zero (already zero-filled)
    hdr[60:64] = w32(pe_offset)      # e_lfanew
    return bytes(hdr)


# ── Section header (40 bytes each) ────────────────────────────────────────────

def section_header(name: str, vsize: int, rva: int, raw_size: int,
                   raw_off: int, chars: int) -> bytes:
    raw_name = name.encode("ascii")[:8].ljust(8, b"\x00")
    return (raw_name + w32(vsize) + w32(rva) + w32(raw_size) + w32(raw_off)
            + w32(0) + w32(0) + w16(0) + w16(0) + w32(chars))


# ── Import section builder ────────────────────────────────────────────────────

def build_import_section(dll_imports: list[dict], base_rva: int) -> bytes:
    """
    Build a minimal Import Directory Table parseable by pefile.

    dll_imports: list of {"dll": "kernel32.dll", "funcs": ["ExitProcess", ...]}
    base_rva:    the VirtualAddress of this section in the PE image.

    Layout inside the section blob:
      [0]            Import Directory Table (IDT): (n_dlls+1) × 20-byte entries
      [IDT_end...]   For each DLL:
                       DLL name string (null-terminated)
                       Hint/Name entries (2-byte hint + name + null, word-aligned)
                       INT (n+1 RVA DWORDs, null-terminated)
                       IAT (identical to INT)
    """
    n = len(dll_imports)
    IDT_BYTES = (n + 1) * 20   # +1 for null terminator

    blob = bytearray(IDT_BYTES)  # pre-allocate IDT, fill later

    meta = []

    for d in dll_imports:
        # DLL name
        dll_name_off = len(blob)
        blob += d["dll"].encode("ascii") + b"\x00"

        # Hint/Name entries
        hn_offsets = []
        for fn in d["funcs"]:
            # word-align
            if len(blob) % 2:
                blob += b"\x00"
            hn_offsets.append(len(blob))
            blob += w16(0)                          # hint = 0
            blob += fn.encode("ascii") + b"\x00"

        # word-align before tables
        if len(blob) % 4:
            blob += b"\x00" * (4 - len(blob) % 4)

        # INT
        int_off = len(blob)
        for ho in hn_offsets:
            blob += w32(base_rva + ho)
        blob += w32(0)

        # IAT (same as INT)
        iat_off = len(blob)
        for ho in hn_offsets:
            blob += w32(base_rva + ho)
        blob += w32(0)

        meta.append({
            "name_rva": base_rva + dll_name_off,
            "int_rva":  base_rva + int_off,
            "iat_rva":  base_rva + iat_off,
        })

    # Write IDT entries now that we have all RVAs
    idt_buf = bytearray()
    for m in meta:
        idt_buf += w32(m["int_rva"])    # OriginalFirstThunk
        idt_buf += w32(0)               # TimeDateStamp
        idt_buf += w32(0)               # ForwarderChain
        idt_buf += w32(m["name_rva"])   # Name RVA
        idt_buf += w32(m["iat_rva"])    # FirstThunk (IAT)
    idt_buf += b"\x00" * 20            # null terminator

    blob[:IDT_BYTES] = idt_buf
    return bytes(blob)


# ── PE assembler ──────────────────────────────────────────────────────────────

class Section:
    def __init__(self, name: str, data: bytes, chars: int):
        self.name  = name
        self.data  = data
        self.chars = chars


def assemble_pe(sections: list[Section], imports: list[dict] | None = None,
                ep_section_name: str | None = None,
                ep_offset_in_section: int = 0) -> bytes:
    """
    Assemble a minimal but pefile-parseable PE32 binary.

    sections:              list of Section objects (in order, .text first)
    imports:               list of {"dll": ..., "funcs": [...]} or None
    ep_section_name:       name of section containing EP (default: first section)
    ep_offset_in_section:  byte offset from that section's start
    """
    # ── Fixed sizes ────────────────────────────────────────────────────────────
    DOS_HDR_SIZE   = 64
    PE_SIG_SIZE    = 4
    COFF_HDR_SIZE  = 20
    OPT_HDR_SIZE   = 0xE0   # PE32 optional header (224 bytes)
    SEC_ENTRY_SIZE = 40

    all_sections = list(sections)

    # We need to know import section RVA before building it, but we don't know
    # the layout until we count all sections.  Solve with a two-pass:
    # Pass 1: layout without import section to find import section RVA.
    # Pass 2: build import data, then final layout.

    def layout(sec_list: list[Section]):
        """Compute (headers_file_size, [(section, rva, raw_off, raw_size)]) """
        n_secs = len(sec_list)
        hdr_raw  = DOS_HDR_SIZE + PE_SIG_SIZE + COFF_HDR_SIZE + OPT_HDR_SIZE + n_secs * SEC_ENTRY_SIZE
        hdr_file = align_to(hdr_raw, FILE_ALIGN)
        hdr_virt = align_to(hdr_raw, SECTION_ALIGN)

        laid = []
        cur_rva  = hdr_virt
        cur_file = hdr_file
        for sec in sec_list:
            raw_size = align_to(len(sec.data), FILE_ALIGN)
            laid.append((sec, cur_rva, cur_file, raw_size))
            cur_rva  += align_to(len(sec.data), SECTION_ALIGN)
            cur_file += raw_size
        return hdr_file, hdr_raw, laid, cur_rva, cur_file

    # Pass 1: get next free RVA if we add an import section
    if imports:
        _, _, laid1, next_rva, next_file = layout(all_sections)
        import_rva   = next_rva
        import_bytes = build_import_section(imports, import_rva)
        import_sec   = Section(".idata", import_bytes, 0xC0000040)
        all_sections = list(sections) + [import_sec]
    else:
        import_rva   = 0
        import_bytes = b""

    # Pass 2: final layout with import section included
    hdr_file, hdr_raw, laid, total_rva, _ = layout(all_sections)
    image_size = align_to(total_rva, SECTION_ALIGN)

    # Determine entry point RVA
    ep_rva = laid[0][1]   # default: first section
    for (sec, rva, _, _) in laid:
        if ep_section_name and sec.name == ep_section_name:
            ep_rva = rva + ep_offset_in_section
            break

    # ── DOS header (64 bytes, e_lfanew = 64) ──────────────────────────────────
    pe_offset = DOS_HDR_SIZE
    buf = bytearray()
    buf += dos_header(pe_offset)

    # ── PE signature ──────────────────────────────────────────────────────────
    buf += b"PE\x00\x00"

    # ── COFF header (20 bytes) ────────────────────────────────────────────────
    buf += w16(0x014C)                   # Machine: x86
    buf += w16(len(all_sections))        # NumberOfSections
    buf += w32(0x5A4D5A4D)              # TimeDateStamp (synthetic)
    buf += w32(0)                        # PointerToSymbolTable
    buf += w32(0)                        # NumberOfSymbols
    buf += w16(OPT_HDR_SIZE)            # SizeOfOptionalHeader
    buf += w16(0x0102)                   # Characteristics: executable + 32-bit

    # ── Optional header (224 bytes) ───────────────────────────────────────────
    code_size = sum(align_to(len(s.data), FILE_ALIGN) for s, *_ in laid
                    if ".idata" not in s.name)
    base_of_code = laid[0][1]

    opt_start = len(buf)
    buf += w16(0x010B)         # Magic: PE32
    buf += bytes([14, 0])      # LinkerVersion
    buf += w32(code_size)      # SizeOfCode
    buf += w32(0)              # SizeOfInitializedData
    buf += w32(0)              # SizeOfUninitializedData
    buf += w32(ep_rva)         # AddressOfEntryPoint
    buf += w32(base_of_code)   # BaseOfCode
    buf += w32(0)              # BaseOfData
    buf += w32(IMAGE_BASE)     # ImageBase
    buf += w32(SECTION_ALIGN)  # SectionAlignment
    buf += w32(FILE_ALIGN)     # FileAlignment
    buf += w16(5) + w16(1)     # OS version
    buf += w16(0) + w16(0)     # Image version
    buf += w16(5) + w16(1)     # Subsystem version
    buf += w32(0)              # Win32VersionValue
    buf += w32(image_size)     # SizeOfImage
    buf += w32(hdr_file)       # SizeOfHeaders
    buf += w32(0)              # CheckSum
    buf += w16(2)              # Subsystem: GUI
    buf += w16(0)              # DllCharacteristics
    buf += w32(0x100000)       # SizeOfStackReserve
    buf += w32(0x1000)         # SizeOfStackCommit
    buf += w32(0x100000)       # SizeOfHeapReserve
    buf += w32(0x1000)         # SizeOfHeapCommit
    buf += w32(0)              # LoaderFlags
    buf += w32(16)             # NumberOfRvaAndSizes

    # Data directories (16 × 8 bytes = 128 bytes)
    buf += w32(0) + w32(0)                              # [0] export
    buf += w32(import_rva) + w32(len(import_bytes))     # [1] import
    for _ in range(14):
        buf += w32(0) + w32(0)                          # [2-15] unused

    opt_actual = len(buf) - opt_start
    assert opt_actual == OPT_HDR_SIZE, f"Opt header size mismatch: {opt_actual}"

    # ── Section headers ────────────────────────────────────────────────────────
    for (sec, rva, raw_off, raw_size) in laid:
        buf += section_header(sec.name, len(sec.data), rva, raw_size, raw_off, sec.chars)

    # ── Pad to file alignment ─────────────────────────────────────────────────
    while len(buf) < hdr_file:
        buf += b"\x00"

    # ── Section raw data ──────────────────────────────────────────────────────
    for (sec, rva, raw_off, raw_size) in laid:
        padded = sec.data + b"\x00" * (raw_size - len(sec.data))
        buf += padded

    return bytes(buf)


# ── Sample definitions ─────────────────────────────────────────────────────────

def build_benign() -> bytes:
    """
    benign.exe — Structurally normal PE.
    3 sections, low entropy, common benign imports, EP in .text.
    Expected verdict: BENIGN (score ≤ 10).
    """
    return assemble_pe(
        sections=[
            Section(".text",  low_entropy_bytes(0x400),  0x60000020),
            Section(".data",  b"\x00" * 0x200,           0xC0000040),
            Section(".rdata", b"ScanForge Benign Demo\x00" + b"\x00" * 0xDA,
                    0x40000040),
        ],
        imports=[
            {"dll": "kernel32.dll", "funcs": ["ExitProcess", "GetLastError", "CloseHandle"]},
            {"dll": "user32.dll",   "funcs": ["MessageBoxA", "GetMessageA"]},
        ],
        ep_section_name=".text",
    )


def build_packed() -> bytes:
    """
    packed.exe — Simulates a packed/encrypted binary.
    1 section, very high entropy (~7.9), no import table, EP at section start.
    Expected verdict: MALICIOUS
      entropy(30) + no_iat(20) + low_sections(10) = 60
    """
    return assemble_pe(
        sections=[
            Section(".packed", high_entropy_bytes(0x800, seed=1337), 0xE0000060),
        ],
        imports=None,   # no import table
        ep_section_name=".packed",
    )


def build_suspicious_imports() -> bytes:
    """
    suspicious_imports.exe — Normal structure, dangerous API imports.
    3 sections, low entropy, imports process-injection APIs.
    Expected verdict: SUSPICIOUS/MALICIOUS driven by API imports factor.
      apis: VirtualAlloc(8)+WriteProcessMemory(8)+CreateRemoteThread(8)+OpenProcess(8)
            +NtUnmapViewOfSection(8) = 40, capped at 32
      Total = 32
    """
    return assemble_pe(
        sections=[
            Section(".text",  low_entropy_bytes(0x600),  0x60000020),
            Section(".data",  b"\x00" * 0x300,           0xC0000040),
            Section(".rdata", b"ScanForge Suspicious-Imports Demo\x00" + b"\x00" * 0xBE,
                    0x40000040),
        ],
        imports=[
            {"dll": "kernel32.dll", "funcs": [
                "ExitProcess",
                "GetLastError",
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "OpenProcess",
            ]},
            {"dll": "ntdll.dll", "funcs": [
                "NtUnmapViewOfSection",
            ]},
        ],
        ep_section_name=".text",
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    samples = {
        "benign.exe":             build_benign,
        "packed.exe":             build_packed,
        "suspicious_imports.exe": build_suspicious_imports,
    }

    for filename, builder in samples.items():
        path = os.path.join(SAMPLES_DIR, filename)
        data = builder()
        with open(path, "wb") as f:
            f.write(data)
        print(f"[generate_samples] Wrote {filename!r:35s} ({len(data):,} bytes)")

    print("[generate_samples] Done.")


if __name__ == "__main__":
    main()
