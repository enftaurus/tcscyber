"""
main.py — ScanForge FastAPI backend.

Endpoints:
  GET  /health                → liveness probe
  POST /analyze               → multipart upload → JSON result
  POST /analyze/stream        → multipart upload → SSE step-by-step stream
  GET  /sample/{name}         → analyze a pre-loaded synthetic sample (JSON)
  GET  /sample/{name}/stream  → pre-loaded sample as SSE stream

Pipeline (in order, same for every file):
  1. File received     — read bytes, check extension + size cap
  2. ZIP extraction    — if .zip, unpack in-memory (bomb-safe)
  3. SHA-256 hash      — fingerprint
  4. Known-hash check  — exact match against the hash blocklist
                         (ships with exactly one entry: EICAR)
  5. PE parsing        — pefile reads MZ → PE headers
  6. Entropy analysis  — Shannon entropy per section (detects packing)
  7. Import table      — count imports, flag known-bad APIs
  8. Entry point       — is EP inside .text or somewhere else?
  9. Scoring + verdict — additive weighted heuristics → 0-100
                         (a hash hit pins MALICIOUS/100, structural
                         factors are still computed and reported)

The uploaded/sample file is NEVER written to disk or executed.
All analysis is performed in-memory via static byte inspection.
A hash hit never short-circuits the pipeline — every remaining step
still runs and its findings stay in the report.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import analyzer
import scorer
import signatures

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("scanforge")


# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScanForge",
    description="Static PE threat analysis — no binary execution, ever.",
    version="1.2.0",
)

_allowed_origins_env = os.environ.get("SCANFORGE_ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS = (
    [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
    if _allowed_origins_env else ["*"]
)
if "*" in ALLOWED_ORIGINS:
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

# Samples served purely from memory, never from disk — an on-disk eicar.com
# gets quarantined by the host's own antivirus (Windows Defender included).
IN_MEMORY_SAMPLES = {
    "eicar.com": lambda: signatures.EICAR_STRING,
}

if FRONTEND_DIR.exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


@app.middleware("http")
async def no_cache_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal error while analysing the file."},
    )


# ── ZIP safety limits ─────────────────────────────────────────────────────────
MAX_ZIP_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
MAX_ZIP_ENTRY_UNCOMPRESSED = 50  * 1024 * 1024
MAX_ZIP_ENTRIES            = 500
MAX_ZIP_DEPTH              = 2
_ZIP_READ_CHUNK            = 1024 * 1024
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


# ── ZIP handling ──────────────────────────────────────────────────────────────

class ZipSafetyError(Exception):
    pass


@dataclass
class _ZipEntry:
    display_name: str
    data: bytes


def _read_entry_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes:
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
                    f"'{info.filename}' exceeded the {cap // (1024*1024)} MB "
                    "decompression limit (possible ZIP bomb)."
                )
            chunks.append(chunk)
    return b"".join(chunks)


def _flatten_zip(raw_bytes: bytes, label: str, depth: int,
                 budget: Dict[str, int], entries: List[_ZipEntry]) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        entries.append(_ZipEntry(label or "archive", raw_bytes))
        return

    try:
        for info in zf.infolist():
            if info.is_dir():
                continue
            budget["count"] += 1
            if budget["count"] > MAX_ZIP_ENTRIES:
                raise ZipSafetyError(
                    f"archive contains more than {MAX_ZIP_ENTRIES} files — aborted."
                )
            display_name = f"{label} > {info.filename}" if label else info.filename
            per_entry_cap = min(MAX_ZIP_ENTRY_UNCOMPRESSED, budget["remaining"])
            if info.file_size > per_entry_cap:
                raise ZipSafetyError(
                    f"'{info.filename}' declares {info.file_size:,} bytes, "
                    "exceeding the safe decompression budget (possible ZIP bomb)."
                )
            try:
                data = _read_entry_capped(zf, info, per_entry_cap)
            except RuntimeError:
                entries.append(_ZipEntry(f"{display_name} [password-protected]", b""))
                continue
            except ZipSafetyError:
                raise
            except Exception:
                entries.append(_ZipEntry(f"{display_name} [unreadable]", b""))
                continue
            budget["remaining"] -= len(data)
            child_ext = os.path.splitext(info.filename)[1].lower()
            if child_ext == ".zip" and depth < MAX_ZIP_DEPTH and data:
                _flatten_zip(data, display_name, depth + 1, budget, entries)
            else:
                entries.append(_ZipEntry(display_name, data))
    finally:
        zf.close()


# ── Core streaming pipeline ───────────────────────────────────────────────────

async def _pipeline_stream(filename: str, raw_bytes: bytes,
                            archive_ctx: Optional[Dict] = None,
                            skip_received: bool = False
                            ) -> AsyncGenerator[str, None]:
    """
    Emit SSE events for each stage of the analysis pipeline.

    Every event is a JSON object with a 'step' field identifying the stage.
    The final event has step='complete' and contains the full result.
    `skip_received` lets the ZIP wrapper reuse this generator without
    duplicating the 'received' step it already emitted.
    """

    def _sse(payload: Dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    # ── Step 1: Received ──────────────────────────────────────────────────────
    if not skip_received:
        yield _sse({"step": "received",
                    "filename": filename,
                    "size": len(raw_bytes)})
        await asyncio.sleep(0.12)

    # ── Step 3: SHA-256 hash ──────────────────────────────────────────────────
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    yield _sse({"step": "hashing", "sha256": sha256})
    await asyncio.sleep(0.12)

    # ── Step 4: Known-hash check (blocklist ships with exactly one entry) ─────
    match = signatures.match_hash(sha256)
    yield _sse({"step": "hash_check",
                "matched": match is not None,
                "name": match.name if match else None})
    await asyncio.sleep(0.12)

    # ── Step 5: PE parsing ────────────────────────────────────────────────────
    features = analyzer.extract_features(raw_bytes)

    if features.get("parse_error"):
        yield _sse({"step": "pe_parse", "ok": False,
                    "error": "No MZ/PE header found — not a Windows executable"})
        await asyncio.sleep(0.10)
        if match:
            # Known-bad but not a PE (EICAR is a DOS COM stub): full report
            # with raw-byte stats and the hash factor pinning MALICIOUS/100.
            raw_entropy = features.get("raw_byte_entropy", 0.0)
            feat_view = {**features,
                         "avg_section_entropy": raw_entropy,
                         "max_section_entropy": raw_entropy}
            score_result = scorer.apply_signature_match(
                scorer.ScoreResult(risk_score=0.0, verdict="BENIGN", factors=[]),
                match)
            yield _sse({"step": "scoring",
                        "risk_score": score_result.risk_score,
                        "verdict":    score_result.verdict,
                        "factors":    [{"label": f.label, "weight": f.weight}
                                       for f in score_result.factors]})
            await asyncio.sleep(0.12)
            result = _build_response(filename, feat_view, score_result, extra={
                "signature_match": match.name,
                "parse_note": (
                    "This file is not a PE binary, so structural PE heuristics "
                    "do not apply — entropy shown is over the raw bytes. The "
                    "known-hash check identified it exactly."
                ),
                **(archive_ctx or {}),
            })
            log.info("hash match (stream): filename=%s name=%s", filename, match.name)
            yield _sse({"step": "complete", "result": result})
            return
        result = _not_pe_response(filename, features)
        if archive_ctx:
            result.update(archive_ctx)
        yield _sse({"step": "complete", "result": result})
        return

    yield _sse({"step": "pe_parse",
                "ok": True,
                "num_sections": features["num_sections"]})
    await asyncio.sleep(0.15)

    # ── Step 5: Entropy analysis ──────────────────────────────────────────────
    yield _sse({"step": "entropy",
                "avg": features["avg_section_entropy"],
                "max": features["max_section_entropy"]})
    await asyncio.sleep(0.15)

    # ── Step 6: Import table ──────────────────────────────────────────────────
    yield _sse({"step": "imports",
                "total":     features["num_imports"],
                "no_iat":    features["no_import_table"],
                "suspicious": features["suspicious_apis_found"]})
    await asyncio.sleep(0.15)

    # ── Step 7: Entry point check ─────────────────────────────────────────────
    yield _sse({"step": "ep_check",
                "outside_text": features["ep_outside_text"]})
    await asyncio.sleep(0.15)

    # ── Step 9: Scoring + Verdict ─────────────────────────────────────────────
    score_result = scorer.score(features)
    if match:
        # Hash hit on a valid PE: keep every structural factor, pin the verdict
        score_result = scorer.apply_signature_match(score_result, match)
    yield _sse({"step": "scoring",
                "risk_score": score_result.risk_score,
                "verdict":    score_result.verdict,
                "factors":    [{"label": f.label, "weight": f.weight}
                               for f in score_result.factors]})
    await asyncio.sleep(0.12)

    # ── Complete ───────────────────────────────────────────────────────────────
    extra: Dict[str, Any] = dict(archive_ctx or {})
    if match:
        extra["signature_match"] = match.name
    result = _build_response(filename, features, score_result,
                             extra=extra or None)
    log.info("analyzed (stream): filename=%s sha256=%s verdict=%s score=%s",
             filename, sha256, score_result.verdict, score_result.risk_score)
    yield _sse({"step": "complete", "result": result})


async def _zip_pipeline_stream(zip_filename: str,
                               raw_bytes: bytes) -> AsyncGenerator[str, None]:
    """
    For ZIP uploads: flatten the archive, then run the pipeline on the
    first valid PE found (or the first file if none are PEs).
    """
    def _sse(payload: Dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    # Validate it's actually a zip
    try:
        zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        async for event in _pipeline_stream(zip_filename, raw_bytes):
            yield event
        return

    yield _sse({"step": "received",
                "filename": zip_filename,
                "size": len(raw_bytes)})
    await asyncio.sleep(0.12)

    # Flatten archive
    budget = {"remaining": MAX_ZIP_TOTAL_UNCOMPRESSED, "count": 0}
    entries: List[_ZipEntry] = []
    try:
        _flatten_zip(raw_bytes, "", depth=1, budget=budget, entries=entries)
    except ZipSafetyError as exc:
        yield _sse({"step": "zip_extract", "ok": False, "error": str(exc)})
        await asyncio.sleep(0.10)
        feats = {"sha256": hashlib.sha256(raw_bytes).hexdigest(),
                 "file_size": len(raw_bytes), "raw_byte_entropy": 0.0}
        yield _sse({"step": "complete",
                    "result": _not_pe_response(zip_filename, feats, str(exc))})
        return

    all_names = [e.display_name for e in entries]
    real_entries = [e for e in entries if e.data]

    yield _sse({"step": "zip_extract",
                "ok": True,
                "files": all_names[:10],
                "total_files": len(all_names)})
    await asyncio.sleep(0.12)

    if not real_entries:
        feats = {"sha256": hashlib.sha256(raw_bytes).hexdigest(),
                 "file_size": len(raw_bytes), "raw_byte_entropy": 0.0}
        yield _sse({"step": "complete",
                    "result": _not_pe_response(zip_filename, feats,
                              "No readable files found in archive.")})
        return

    # Find the best candidate: PE-priority sort
    def _sort_key(e: _ZipEntry) -> int:
        return 0 if os.path.splitext(e.display_name)[1].lower() in _PE_PRIORITY_EXTS else 1

    candidate = sorted(real_entries, key=_sort_key)[0]
    contents_preview = ", ".join(all_names[:8]) + ("…" if len(all_names) > 8 else "")
    archive_ctx = {
        "archive_name": zip_filename,
        "archive_note": (
            f"Analysed '{candidate.display_name}' extracted from '{zip_filename}'. "
            f"Archive contained {len(all_names)} file(s): {contents_preview}."
        ),
    }

    # Stream the inner file through the full pipeline
    # (skip the 'received' step — already emitted before zip_extract)
    async for event in _pipeline_stream(candidate.display_name, candidate.data,
                                        archive_ctx=archive_ctx,
                                        skip_received=True):
        yield event


# ── Routes ────────────────────────────────────────────────────────────────────

ALLOWED_EXTS = {".exe", ".dll", ".zip", ".txt", ".bin", ".com"}


def _validate_upload(filename: str, raw_bytes: bytes) -> None:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Accepted: {', '.join(sorted(ALLOWED_EXTS))}",
        )
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(raw_bytes) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 50 MB limit.")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    """Classic JSON endpoint — returns the full result in one response."""
    filename  = file.filename or "unknown"
    raw_bytes = await file.read()
    _validate_upload(filename, raw_bytes)

    ext = os.path.splitext(filename)[1].lower()
    if ext == ".zip":
        # Collect the full stream and return the last 'complete' event's result
        result: Dict = {}
        async for event in _zip_pipeline_stream(filename, raw_bytes):
            data = json.loads(event.replace("data: ", "").strip())
            if data.get("step") == "complete":
                result = data.get("result", {})
    else:
        result = {}
        async for event in _pipeline_stream(filename, raw_bytes):
            data = json.loads(event.replace("data: ", "").strip())
            if data.get("step") == "complete":
                result = data.get("result", {})

    log.info("analyzed: filename=%s verdict=%s score=%s",
             filename, result.get("verdict"), result.get("risk_score"))
    return JSONResponse(result)


@app.post("/analyze/stream")
async def analyze_stream(file: UploadFile = File(...)):
    """SSE streaming endpoint — emits one event per pipeline step."""
    filename  = file.filename or "unknown"
    raw_bytes = await file.read()
    _validate_upload(filename, raw_bytes)

    ext = os.path.splitext(filename)[1].lower()
    gen = (_zip_pipeline_stream(filename, raw_bytes)
           if ext == ".zip"
           else _pipeline_stream(filename, raw_bytes))

    return StreamingResponse(
        gen,
        media_type="text/event-stream",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
        },
    )


def _load_sample_bytes(name: str) -> bytes:
    """Resolve a sample's bytes: in-memory samples first, then disk."""
    if name not in ALLOWED_SAMPLE_NAMES:
        raise HTTPException(status_code=404,
            detail=f"Unknown sample '{name}'. Valid: {sorted(ALLOWED_SAMPLE_NAMES)}")
    if name in IN_MEMORY_SAMPLES:
        return IN_MEMORY_SAMPLES[name]()
    sample_path = SAMPLES_DIR / name
    if not sample_path.exists():
        raise HTTPException(status_code=503,
            detail=f"Sample '{name}' not found. Run generate_samples.py first.")
    return sample_path.read_bytes()


@app.get("/sample/{name}")
async def analyze_sample(name: str):
    """Classic JSON endpoint for pre-loaded samples."""
    raw_bytes = _load_sample_bytes(name)
    result: Dict = {}
    async for event in _pipeline_stream(name, raw_bytes):
        data = json.loads(event.replace("data: ", "").strip())
        if data.get("step") == "complete":
            result = data.get("result", {})
    return JSONResponse(result)


@app.get("/sample/{name}/stream")
async def stream_sample(name: str):
    """SSE streaming endpoint for pre-loaded samples."""
    raw_bytes = _load_sample_bytes(name)
    return StreamingResponse(
        _pipeline_stream(name, raw_bytes),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@app.get("/samples")
def list_samples():
    return {"samples": sorted(ALLOWED_SAMPLE_NAMES)}
