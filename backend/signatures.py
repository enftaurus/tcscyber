"""
signatures.py — Known-hash detection for ScanForge.

A minimal hash-blocklist layer that runs as its own pipeline step, right
after SHA-256 hashing and before PE structural analysis. Detection is a
pure exact-hash comparison — nothing here executes, decodes, or
interprets file content.

Exactly ONE hash ships pre-loaded: the canonical 68-byte EICAR Standard
Anti-Virus Test File. That is deliberate — it demonstrates the known-hash
detection path end-to-end while keeping the blocklist honest about what
it is: a starting point you would feed from a real threat-intel hash
feed, not a bundled malware database.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SignatureMatch:
    name: str
    category: str      # "test-file" | "known-malware"
    detail: str


# The EICAR test string — kept ONLY so the backend can serve the EICAR demo
# sample in-memory (see IN_MEMORY_SAMPLES in main.py). It is NOT used for
# detection; detection is exact-hash only.
EICAR_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# ── Known-hash blocklist: exactly one pre-existing entry ─────────────────────
# SHA-256 of the canonical 68-byte eicar.com. Extend from a real hash feed
# for production use.
KNOWN_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR-Test-File",
}


def match_hash(sha256: str) -> Optional[SignatureMatch]:
    """Exact SHA-256 lookup against the known-hash blocklist."""
    name = KNOWN_HASHES.get(sha256)
    if name is None:
        return None
    return SignatureMatch(
        name=name,
        category="test-file",
        detail=(
            f"File hash {sha256} exactly matches the known {name} entry in "
            "the hash blocklist. This is the industry-standard test file "
            "used to verify a scanner's detection path — it contains no "
            "live payload."
        ),
    )
