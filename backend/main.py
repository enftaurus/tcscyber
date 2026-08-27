"""
main.py — ScanForge FastAPI backend.

Endpoints:
  GET  /health              → liveness probe
  POST /analyze             → multipart file upload → JSON analysis result
  GET  /sample/{name}       → analyze a pre-loaded synthetic sample by name

The uploaded/sample file is NEVER written to disk or executed.
All analysis is performed in-memory via static byte inspection.
ZIP archives are unpacked in-memory; each contained file is probed as a PE.
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import analyzer
import scorer

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ScanForge",
    description="Static PE threat analysis — no binary execution, ever.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

SAMPLES_DIR  = Path(__file__).parent / "samples"
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
ALLOWED_SAMPLE_NAMES = {"benign.exe", "packed.exe", "suspicious_imports.exe"}

if FRONTEND_DIR.exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


# ── PE-likely extensions to prioritise inside a ZIP ───────────────────────────
_PE_PRIORITY_EXTS = {".exe", ".dll", ".com", ".bin", ".sys", ".drv", ".ocx"}


# ── Response builders ─────────────────────────────────────────────────────────

def _build_response(filename: str, features: Dict[str, Any],
                    score_result: scorer.ScoreResult,
                    extra: Optional[Dict] = None) -> Dict:
    resp: Dict[str, Any] = {
        "filename":              filename,
        "sha256":                features["sha256"],
        "file_size":             features["file_size"],
        "verdict":               score_result.verdict,
        "risk_score":            score_result.risk_score,
        "num_sections":          features["num_sections"],
        "avg_section_entropy":   features["avg_section_entropy"],
        "max_section_entropy":   features["max_section_entropy"],
        "num_imports":           features["num_imports"],
        "suspicious_api_count":  features["suspicious_api_count"],
        "suspicious_apis_found": features["suspicious_apis_found"],
        "factors": [
            {"label": f.label, "weight": f.weight, "detail": f.detail}
            for f in score_result.factors
        ],
    }
    if extra:
        resp.update(extra)
    return resp


def _not_pe_response(filename: str, features: Dict,
                     parse_note: Optional[str] = None) -> Dict:
    """Graceful partial-analysis result for files that are not valid PEs."""
    raw_entropy = features.get("raw_byte_entropy", 0.0)
    note = parse_note or (
        "This file does not have a valid PE/MZ header. "
        "Structural PE analysis was skipped. "
        "SHA-256 and raw-byte entropy are shown below."
    )
    return {
        "filename":              filename,
        "sha256":                features["sha256"],
        "file_size":             features["file_size"],
        "verdict":               "NOT A PE FILE",
        "risk_score":            0.0,
        "num_sections":          0,
        "avg_section_entropy":   raw_entropy,
        "max_section_entropy":   raw_entropy,
        "num_imports":           0,
        "suspicious_api_count":  0,
        "suspicious_apis_found": [],
        "not_pe":                True,
        "parse_note":            note,
        "factors":               [],
    }


def _analyze_bytes(filename: str, raw_bytes: bytes) -> Dict:
    """Parse and score raw bytes as a PE. Returns a graceful response if not a PE."""
    features = analyzer.extract_features(raw_bytes)
    if features.get("parse_error"):
        return _not_pe_response(filename, features)
    score_result = scorer.score(features)
    return _build_response(filename, features, score_result)


def _analyze_zip(zip_filename: str, raw_bytes: bytes) -> Dict:
    """
    Unpack a ZIP archive entirely in-memory and analyse the first valid PE found.

    Strategy:
      1. Try to open as a ZIP; if it fails, fall back to raw PE analysis.
      2. Prefer files whose extension suggests a PE (.exe, .dll, .com …).
      3. Try every non-directory file, skipping those that fail PE parsing.
      4. Return full analysis for the first successful PE parse.
      5. If no PE found, return a descriptive NOT_A_PE response listing contents.

    No bytes are ever written to disk or executed.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        # Misnamed file — not actually a ZIP, probe raw bytes directly
        return _analyze_bytes(zip_filename, raw_bytes)

    all_names: List[str] = [m.filename for m in zf.infolist() if not m.is_dir()]

    if not all_names:
        feats: Dict[str, Any] = {
            "sha256":           hashlib.sha256(raw_bytes).hexdigest(),
            "file_size":        len(raw_bytes),
            "raw_byte_entropy": 0.0,
        }
        return _not_pe_response(
            zip_filename, feats,
            parse_note="The ZIP archive is empty — no files to analyse.",
        )

    # Sort: PE-likely extensions first, everything else after
    def _sort_key(name: str) -> int:
        return 0 if os.path.splitext(name)[1].lower() in _PE_PRIORITY_EXTS else 1

    ordered = sorted(all_names, key=_sort_key)

    for name in ordered:
        try:
            member_bytes = zf.read(name)
        except Exception:
            continue
        if not member_bytes:
            continue

        features = analyzer.extract_features(member_bytes)
        if not features.get("parse_error"):
            # Found a valid PE inside the archive — full analysis
            score_result = scorer.score(features)
            contents_preview = ", ".join(all_names[:8])
            if len(all_names) > 8:
                contents_preview += "…"
            return _build_response(
                filename=name,
                features=features,
                score_result=score_result,
                extra={
                    "archive_name": zip_filename,
                    "archive_note": (
                        f"Analysed '{name}' extracted from '{zip_filename}'. "
                        f"Archive contained {len(all_names)} file(s): {contents_preview}."
                    ),
                },
            )

    # No valid PE found in the archive
    contents_str = ", ".join(all_names[:10])
    if len(all_names) > 10:
        contents_str += "…"

    feats = {
        "sha256":           hashlib.sha256(raw_bytes).hexdigest(),
        "file_size":        len(raw_bytes),
        "raw_byte_entropy": 0.0,
    }
    return _not_pe_response(
        zip_filename, feats,
        parse_note=(
            f"No valid PE executable found inside '{zip_filename}'. "
            f"Files in archive: {contents_str}. "
            "Note: the EICAR test file is a DOS COM stub, not a full PE — "
            "PE structural analysis does not apply to it. "
            "The archive was received and inspected safely without execution."
        ),
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    """
    Upload a file for static analysis.

    .zip archives are unpacked in-memory; the first valid PE found is analysed.
    The file is NEVER written to disk, executed, or mapped as a process.
    """
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()

    ALLOWED_EXTS = {".exe", ".dll", ".zip", ".txt", ".bin"}
    if ext not in ALLOWED_EXTS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Accepted: {', '.join(sorted(ALLOWED_EXTS))}",
        )

    raw_bytes = await file.read()

    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(raw_bytes) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 50 MB limit.")

    if ext == ".zip":
        return JSONResponse(_analyze_zip(filename, raw_bytes))

    return JSONResponse(_analyze_bytes(filename, raw_bytes))


@app.get("/sample/{name}")
def analyze_sample(name: str):
    """Analyse one of the three pre-loaded synthetic samples by name."""
    if name not in ALLOWED_SAMPLE_NAMES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown sample '{name}'. Valid names: {sorted(ALLOWED_SAMPLE_NAMES)}",
        )

    sample_path = SAMPLES_DIR / name
    if not sample_path.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Sample '{name}' not found on server. Run generate_samples.py first.",
        )

    raw_bytes = sample_path.read_bytes()
    return JSONResponse(_analyze_bytes(name, raw_bytes))


@app.get("/samples")
def list_samples():
    """List available pre-loaded sample names."""
    return {"samples": sorted(ALLOWED_SAMPLE_NAMES)}
