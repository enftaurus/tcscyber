"""
signatures.py — Known-threat signature detection for ScanForge.

PE structural heuristics (analyzer.py / scorer.py) only apply to Windows
Portable Executables. They say nothing about a plain-text/COM test string,
a script, or a known-bad file that isn't a PE at all — which is exactly
what the industry-standard EICAR test file is. Before this module existed,
ScanForge had no way to recognise a known threat unless it happened to
parse as a PE, so EICAR (and anything else non-PE) fell through to a
"NOT A PE FILE / risk 0" response even though every real antivirus engine
flags it immediately.

This module adds a signature layer that runs BEFORE and INDEPENDENTLY of
PE parsing, on every file ScanForge is asked to analyse — raw upload or a
member extracted from a ZIP. Two detection methods:

  1. Exact hash match against a small curated list of known file hashes.
  2. Substring match against known test/threat byte patterns (this is how
     every commercial AV product detects EICAR — it is intentionally
     trivial to detect, by design of the EICAR standard).

Nothing here executes, decodes, or interprets file content as code —
detection is pure byte/string comparison.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class SignatureMatch:
    name: str
    category: str      # "test-file" | "known-malware"
    detail: str


# ── EICAR test string ──────────────────────────────────────────────────────
# The official EICAR Standard Anti-Virus Test File string. Per the EICAR
# specification the string may be embedded anywhere within the first 128
# bytes of a file (optionally padded/trailed with whitespace), so detection
# is a substring search, not an exact-length match. This lets ScanForge
# recognise eicar.com, eicar.com.txt, eicar_com.zip contents, and any
# renamed/padded variant a user might upload.
EICAR_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# ── Known-hash blocklist ────────────────────────────────────────────────────
# SHA-256 of published EICAR test file variants, kept as a defense-in-depth
# exact-match layer alongside the substring check above. Extend this dict
# with additional known-bad hashes as needed — it is intentionally a plain
# data structure so it can be swapped for an external feed later.
KNOWN_HASHES = {
    # Canonical 68-byte eicar.com (no trailing newline)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR-Test-File (68 bytes)",
    # 69-byte variant with a trailing LF
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267":
        "EICAR-Test-File (LF variant)",
    # 70-byte variant distributed with a trailing CRLF (eicar.com.txt)
    "8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71":
        "EICAR-Test-File (CRLF variant)",
}

MAX_SCAN_BYTES = 4 * 1024 * 1024  # signature scan only needs the leading bytes


def scan_signatures(raw_bytes: bytes) -> Optional[SignatureMatch]:
    """
    Check raw file bytes against known-threat signatures.

    Returns a SignatureMatch on hit, or None. Cheap and side-effect free —
    safe to call on every file/archive member before any other analysis.
    """
    if not raw_bytes:
        return None

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if sha256 in KNOWN_HASHES:
        return SignatureMatch(
            name=KNOWN_HASHES[sha256],
            category="test-file",
            detail=(
                f"File hash {sha256} matches the known EICAR Standard "
                "Anti-Virus Test File. This is the industry-standard file "
                "used to verify a scanner is actually detecting threats — "
                "it contains no live payload."
            ),
        )

    # Substring search over the leading window (EICAR spec: within first
    # 128 bytes, but we scan a generous window to also catch it appended
    # after other content, e.g. inside a wrapper/dropper test file).
    window = raw_bytes[:MAX_SCAN_BYTES]
    if EICAR_STRING in window:
        return SignatureMatch(
            name="EICAR-Test-File",
            category="test-file",
            detail=(
                "File contains the EICAR Standard Anti-Virus Test File "
                "string. This is a deliberately detectable test pattern "
                "recognised by every real antivirus engine — it verifies "
                "the scanner's detection path is working. No live payload "
                "is present."
            ),
        )

    return None
