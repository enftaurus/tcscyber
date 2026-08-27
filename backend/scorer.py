"""
scorer.py — Heuristic risk-scoring engine for ScanForge.

Every point in the final score is traceable to a specific structural fact
about the binary. No trained model, no black box — intentional for demo
explainability.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass
class Factor:
    label: str
    weight: float
    detail: str


@dataclass
class ScoreResult:
    risk_score: float
    verdict: str
    factors: List[Factor] = field(default_factory=list)


# ── Heuristic weights ─────────────────────────────────────────────────────────

# Entropy thresholds
ENTROPY_HIGH_THRESHOLD = 7.2   # strong indicator of packing/encryption
ENTROPY_MID_THRESHOLD  = 6.5   # elevated — worth noting

ENTROPY_HIGH_WEIGHT    = 30
ENTROPY_MID_WEIGHT     = 15

# Import-based rules
SUSPICIOUS_APIS = {
    "VirtualAlloc":             "Allocates executable memory — common in shellcode loaders",
    "VirtualAllocEx":           "Allocates memory in remote process — process injection",
    "WriteProcessMemory":       "Writes to another process — process injection",
    "CreateRemoteThread":       "Spawns thread in remote process — classic injection technique",
    "NtUnmapViewOfSection":     "Unmaps process image — process hollowing",
    "SetWindowsHookEx":         "Installs system-wide hook — keylogging / injection",
    "OpenProcess":              "Opens a handle to another process",
    "ReadProcessMemory":        "Reads memory of another process",
    "LoadLibraryA":             "Dynamic library loading — often used to hide imports",
    "GetProcAddress":           "Resolves API at runtime — common in obfuscated loaders",
    "IsDebuggerPresent":        "Anti-debugging check",
    "ZwQueryInformationProcess":"Anti-debugging / sandbox evasion",
}

SUSPICIOUS_API_WEIGHT_EACH = 8   # per distinct API found
SUSPICIOUS_API_MAX_WEIGHT  = 32  # cap so imports alone can't exceed MALICIOUS solo

# Entry point rule
EP_OUTSIDE_TEXT_WEIGHT = 15

# Import table absence
NO_IMPORT_TABLE_WEIGHT = 20

# Very low section count
LOW_SECTION_COUNT_THRESHOLD = 2
LOW_SECTION_COUNT_WEIGHT    = 10

# Verdict thresholds
BENIGN_MAX     = 24
SUSPICIOUS_MAX = 49


def score(features: dict) -> ScoreResult:
    """
    Compute risk score and verdict from extracted PE features.

    Parameters
    ----------
    features : dict
        Output of analyzer.extract_features().

    Returns
    -------
    ScoreResult with risk_score ∈ [0, 100], verdict string, and factor list.
    """
    total   : float       = 0.0
    factors : List[Factor] = []

    # ── 1. Section entropy ────────────────────────────────────────────────────
    max_entropy: float = features.get("max_section_entropy", 0.0)

    if max_entropy > ENTROPY_HIGH_THRESHOLD:
        w = ENTROPY_HIGH_WEIGHT
        total += w
        factors.append(Factor(
            label="High-entropy section (packing / encryption)",
            weight=w,
            detail=(
                f"Max section entropy {max_entropy:.2f} bits/byte exceeds {ENTROPY_HIGH_THRESHOLD} — "
                "strongly consistent with packed or encrypted content."
            ),
        ))
    elif max_entropy > ENTROPY_MID_THRESHOLD:
        w = ENTROPY_MID_WEIGHT
        total += w
        factors.append(Factor(
            label="Elevated section entropy",
            weight=w,
            detail=(
                f"Max section entropy {max_entropy:.2f} bits/byte is above {ENTROPY_MID_THRESHOLD} — "
                "may indicate compression or obfuscation."
            ),
        ))

    # ── 2. Suspicious API imports ─────────────────────────────────────────────
    found_apis: list = features.get("suspicious_apis_found", [])
    if found_apis:
        raw_weight = len(found_apis) * SUSPICIOUS_API_WEIGHT_EACH
        w = min(raw_weight, SUSPICIOUS_API_MAX_WEIGHT)
        total += w
        api_lines = "; ".join(
            f"{api} ({SUSPICIOUS_APIS.get(api, 'flagged API')})"
            for api in found_apis
        )
        factors.append(Factor(
            label="Suspicious API imports",
            weight=w,
            detail=f"Found {len(found_apis)} high-risk import(s): {api_lines}.",
        ))

    # ── 3. Entry point outside .text ─────────────────────────────────────────
    if features.get("ep_outside_text", False):
        w = EP_OUTSIDE_TEXT_WEIGHT
        total += w
        factors.append(Factor(
            label="Entry point outside .text section",
            weight=w,
            detail=(
                "The PE entry point does not fall within the primary code section (.text). "
                "This is common in packers and stub-based loaders."
            ),
        ))

    # ── 4. No import table ────────────────────────────────────────────────────
    if features.get("no_import_table", False):
        w = NO_IMPORT_TABLE_WEIGHT
        total += w
        factors.append(Factor(
            label="No import table (IAT absent)",
            weight=w,
            detail=(
                "The Import Address Table is missing. Legitimate compiler-generated binaries "
                "almost always have one. Absence suggests manual mapping, heavy obfuscation, "
                "or a fully self-contained shellcode stub."
            ),
        ))

    # ── 5. Very low section count ─────────────────────────────────────────────
    num_sections: int = features.get("num_sections", 0)
    if 0 < num_sections <= LOW_SECTION_COUNT_THRESHOLD:
        w = LOW_SECTION_COUNT_WEIGHT
        total += w
        factors.append(Factor(
            label="Abnormally low section count",
            weight=w,
            detail=(
                f"Only {num_sections} section(s) found. Standard compiler-generated PE files "
                f"typically have 3–6 sections (.text, .data, .rdata, etc.)."
            ),
        ))

    # ── Clamp and verdict ─────────────────────────────────────────────────────
    risk_score = min(total, 100.0)

    if risk_score <= BENIGN_MAX:
        verdict = "BENIGN"
    elif risk_score <= SUSPICIOUS_MAX:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return ScoreResult(risk_score=risk_score, verdict=verdict, factors=factors)
