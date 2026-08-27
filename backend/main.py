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
import logging
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import analyzer
import scorer
import signatures

# ── Logging ───────────────────────────────────────────────────────────────────
# Audit trail of what was scanned and what came back — never the file content
# itself, only identifying metadata (name, hash, verdict).

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("scanforge")


# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ScanForge",
    description="Static PE threat analysis — no binary execution, ever.",
    version="1.1.0",
)

# CORS: default is permissive for local/demo use. For a real deployment, set
# SCANFORGE_ALLOWED_ORIGINS to a comma-separated allowlist (e.g.
# "https://scanforge.example.com") so the API isn't callable cross-origin
# from arbitrary sites.
_allowed_origins_env = os.environ.get("SCANFORGE_ALLOWED_ORIGINS", "").strip()
if _allowed_origins_env:
    ALLOWED_ORIGINS = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = ["*"]
    log.warning(
        "SCANFORGE_ALLOWED_ORIGINS not set — CORS is wide open ('*'). "
        "Set it before deploying anywhere reachable by untrusted origins."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

SAMPLES_DIR  = Path(__file__).parent / "samples"
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
ALLOWED_SAMPLE_NAMES = {
    "benign.exe", "packed.exe", "suspicious_imports.exe", "eicar.com",
}

# Samples served purely from memory, never from disk. EICAR must live here:
# any real antivirus (including Windows Defender on the host running this
# server) quarantines/blocks an on-disk eicar.com the moment it is written,
# which would break the demo on exactly the machines it runs on.
IN_MEMORY_SAMPLES = {
    "eicar.com": lambda: signatures.EICAR_STRING,
}

if FRONTEND_DIR.exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Never leak stack traces / internals to the client — log and return a clean 500."""
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal error while analysing the file."},
    )


# ── PE-likely extensions to prioritise inside a ZIP ───────────────────────────
_PE_PRIORITY_EXTS = {".exe", ".dll", ".com", ".bin", ".sys", ".drv", ".ocx"}

# ── ZIP safety limits (defense against decompression / entry-count bombs) ────
MAX_ZIP_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024   # 100 MB aggregate per scan
MAX_ZIP_ENTRY_UNCOMPRESSED = 50 * 1024 * 1024    # 50 MB per individual member
MAX_ZIP_ENTRIES            = 500                  # across the whole archive tree
MAX_ZIP_DEPTH              = 2                    # top-level zip + one nested level
_ZIP_READ_CHUNK             = 1024 * 1024


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


def _analyze_bytes(filename: str, raw_bytes: bytes,
                   extra: Optional[Dict] = None) -> Dict:
    """
    Analyse raw bytes through the FULL pipeline: PE structural analysis
    (entropy, imports, section layout, entry point) plus a known-signature
    scan. A signature hit does not skip the structural pass — it is added
    to the report as the leading factor and pins the verdict to
    MALICIOUS / 100. Returns a graceful response for files that are neither
    a PE nor a signature hit.
    """
    match = signatures.scan_signatures(raw_bytes)
    features = analyzer.extract_features(raw_bytes)

    if features.get("parse_error"):
        if match is None:
            resp = _not_pe_response(filename, features)
            if extra:
                resp.update(extra)
            return resp
        # Known-bad but not a PE (e.g. EICAR, a DOS COM stub) — still produce
        # a full report: hash, size, raw-byte entropy, and the signature factor.
        log.info("signature match: filename=%s signature=%s", filename, match.name)
        raw_entropy = features.get("raw_byte_entropy", 0.0)
        feat_view = {**features,
                     "avg_section_entropy": raw_entropy,
                     "max_section_entropy": raw_entropy}
        score_result = scorer.apply_signature_match(
            scorer.ScoreResult(risk_score=0.0, verdict="BENIGN", factors=[]), match)
        return _build_response(filename, feat_view, score_result, extra={
            "signature_match": match.name,
            "parse_note": (
                "This file is not a PE binary, so structural PE heuristics do "
                "not apply — entropy shown is over the raw bytes. Signature "
                "detection applies to any file type and identified it exactly."
            ),
            **(extra or {}),
        })

    # Valid PE — full structural scoring, with the signature overlay on top
    score_result = scorer.score(features)
    if match:
        log.info("signature match: filename=%s signature=%s", filename, match.name)
        score_result = scorer.apply_signature_match(score_result, match)
        return _build_response(filename, features, score_result,
                               extra={"signature_match": match.name, **(extra or {})})
    return _build_response(filename, features, score_result, extra=extra)


# ── ZIP handling ──────────────────────────────────────────────────────────────

class ZipSafetyError(Exception):
    """Raised when an archive violates a decompression/entry-count safety guard."""


@dataclass
class _ZipEntry:
    display_name: str
    data: bytes  # empty means "present but unreadable" (e.g. password-protected)


def _read_entry_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes:
    """
    Read one ZIP member in chunks, enforcing `cap` against the bytes actually
    produced by decompression — not just the (spoofable) declared size in the
    archive's central directory. This is the real defense against ZIP bombs.
    """
    chunks: List[bytes] = []
    total = 0
    with zf.open(info) as fh:
        while True:
            chunk = fh.read(_ZIP_READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ZipSafetyError(
                    f"'{info.filename}' exceeded the {cap // (1024 * 1024)} MB "
                    "decompression limit while reading (possible ZIP bomb)."
                )
            chunks.append(chunk)
    return b"".join(chunks)


def _flatten_zip(raw_bytes: bytes, label: str, depth: int,
                 budget: Dict[str, int], entries: List[_ZipEntry]) -> None:
    """
    Recursively walk a ZIP's members — one extra level of nested ZIPs is
    followed — appending every real file's bytes to `entries`, entirely
    in-memory. Mutates `budget` in place; raises ZipSafetyError if any
    safety limit (entry count, per-entry size, or aggregate decompressed
    size) is exceeded. Nothing is ever written to disk.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        # Named like a zip (or nested inside one) but isn't actually valid —
        # treat its raw bytes as a plain file entry instead of an archive.
        entries.append(_ZipEntry(label or "archive", raw_bytes))
        return

    try:
        for info in zf.infolist():
            if info.is_dir():
                continue

            budget["count"] += 1
            if budget["count"] > MAX_ZIP_ENTRIES:
                raise ZipSafetyError(
                    f"archive contains more than {MAX_ZIP_ENTRIES} files — aborted for safety."
                )

            display_name = f"{label} > {info.filename}" if label else info.filename
            per_entry_cap = min(MAX_ZIP_ENTRY_UNCOMPRESSED, budget["remaining"])

            if info.file_size > per_entry_cap:
                raise ZipSafetyError(
                    f"'{info.filename}' declares {info.file_size:,} bytes uncompressed, "
                    f"exceeding the safe decompression budget (possible ZIP bomb)."
                )

            try:
                data = _read_entry_capped(zf, info, per_entry_cap)
            except RuntimeError:
                # zipfile raises RuntimeError (not BadZipFile) for encrypted entries
                entries.append(_ZipEntry(f"{display_name} [password-protected, skipped]", b""))
                continue
            except ZipSafetyError:
                raise
            except Exception:
                entries.append(_ZipEntry(f"{display_name} [unreadable, skipped]", b""))
                continue

            budget["remaining"] -= len(data)

            child_ext = os.path.splitext(info.filename)[1].lower()
            if child_ext == ".zip" and depth < MAX_ZIP_DEPTH and data:
                _flatten_zip(data, display_name, depth + 1, budget, entries)
            else:
                entries.append(_ZipEntry(display_name, data))
    finally:
        zf.close()


def _analyze_zip(zip_filename: str, raw_bytes: bytes) -> Dict:
    """
    Unpack a ZIP archive entirely in-memory (one level of nested ZIPs
    included) and scan every contained file — first for known threat
    signatures (catches EICAR and anything else that isn't a PE at all),
    then for PE structural risk. No bytes are ever written to disk or
    executed at any point.

    Strategy:
      1. Try to open as a ZIP; if it fails, fall back to raw analysis.
      2. Flatten all members in-memory, enforcing decompression-bomb,
         entry-count, and per-entry size guards along the way.
      3. Pass 1 — signature scan every extracted file; a hit wins
         immediately and is reported as MALICIOUS regardless of PE-ness.
      4. Pass 2 — PE structural scan, PE-likely extensions first; return
         the first valid PE's full analysis.
      5. Nothing found → a descriptive summary listing archive contents.
    """
    try:
        zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        # Misnamed file — not actually a ZIP, probe raw bytes directly
        return _analyze_bytes(zip_filename, raw_bytes)

    budget = {"remaining": MAX_ZIP_TOTAL_UNCOMPRESSED, "count": 0}
    entries: List[_ZipEntry] = []
    try:
        _flatten_zip(raw_bytes, "", depth=1, budget=budget, entries=entries)
    except ZipSafetyError as exc:
        log.warning("zip rejected: filename=%s reason=%s", zip_filename, exc)
        feats = {
            "sha256":           hashlib.sha256(raw_bytes).hexdigest(),
            "file_size":        len(raw_bytes),
            "raw_byte_entropy": 0.0,
        }
        return _not_pe_response(
            zip_filename, feats,
            parse_note=f"Archive rejected before scanning could complete: {exc}",
        )

    all_names: List[str] = [e.display_name for e in entries]
    real_entries = [e for e in entries if e.data]

    if not real_entries:
        feats = {
            "sha256":           hashlib.sha256(raw_bytes).hexdigest(),
            "file_size":        len(raw_bytes),
            "raw_byte_entropy": 0.0,
        }
        note = ("The ZIP archive is empty — no files to analyse." if not entries else
                "No readable files found in the archive (all entries were empty, "
                "password-protected, or unreadable).")
        return _not_pe_response(zip_filename, feats, parse_note=note)

    def _contents_preview(limit: int) -> str:
        preview = ", ".join(all_names[:limit])
        return preview + ("…" if len(all_names) > limit else "")

    # ── Pass 1: known-signature scan across every extracted file ─────────────
    # A matching entry is then run through the FULL analysis pipeline
    # (structural stats + signature factor), same as a raw upload would be.
    for entry in real_entries:
        match = signatures.scan_signatures(entry.data)
        if match:
            log.info("signature match in zip: archive=%s entry=%s signature=%s",
                     zip_filename, entry.display_name, match.name)
            return _analyze_bytes(
                entry.display_name, entry.data,
                extra={
                    "archive_name": zip_filename,
                    "archive_note": (
                        f"Analysed '{entry.display_name}' extracted from "
                        f"'{zip_filename}'. Archive contained {len(all_names)} "
                        f"file(s): {_contents_preview(8)}."
                    ),
                },
            )

    # ── Pass 2: PE-priority structural scan ───────────────────────────────────
    def _sort_key(e: _ZipEntry) -> int:
        return 0 if os.path.splitext(e.display_name)[1].lower() in _PE_PRIORITY_EXTS else 1

    for entry in sorted(real_entries, key=_sort_key):
        features = analyzer.extract_features(entry.data)
        if not features.get("parse_error"):
            score_result = scorer.score(features)
            return _build_response(
                filename=entry.display_name,
                features=features,
                score_result=score_result,
                extra={
                    "archive_name": zip_filename,
                    "archive_note": (
                        f"Analysed '{entry.display_name}' extracted from '{zip_filename}'. "
                        f"Archive contained {len(all_names)} file(s): {_contents_preview(8)}."
                    ),
                },
            )

    # ── Nothing found ──────────────────────────────────────────────────────────
    feats = {
        "sha256":           hashlib.sha256(raw_bytes).hexdigest(),
        "file_size":        len(raw_bytes),
        "raw_byte_entropy": 0.0,
    }
    return _not_pe_response(
        zip_filename, feats,
        parse_note=(
            f"'{zip_filename}' was scanned safely — known-signature check and PE "
            f"structural analysis both found nothing. Files in archive: "
            f"{_contents_preview(10)}."
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

    ALLOWED_EXTS = {".exe", ".dll", ".zip", ".txt", ".bin", ".com"}
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

    result = _analyze_zip(filename, raw_bytes) if ext == ".zip" else _analyze_bytes(filename, raw_bytes)
    log.info("analyzed: filename=%s sha256=%s verdict=%s score=%s",
             filename, result.get("sha256"), result.get("verdict"), result.get("risk_score"))
    return JSONResponse(result)


@app.get("/sample/{name}")
def analyze_sample(name: str):
    """Analyse one of the pre-loaded demo samples by name."""
    if name not in ALLOWED_SAMPLE_NAMES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown sample '{name}'. Valid names: {sorted(ALLOWED_SAMPLE_NAMES)}",
        )

    if name in IN_MEMORY_SAMPLES:
        # e.g. EICAR — generated at request time, never stored on disk where
        # the host's own antivirus would quarantine it.
        raw_bytes = IN_MEMORY_SAMPLES[name]()
    else:
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
