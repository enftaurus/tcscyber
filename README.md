# ScanForge

Static threat analysis for Windows PE binaries (`.exe`/`.dll`) and ZIP
archives — entirely in-memory, nothing is ever written to disk or executed.

## What changed in this pass

The app previously had **no way to recognise a known threat unless it
happened to parse as a valid PE**. That meant uploading the industry-standard
EICAR test file — raw or zipped — always came back `NOT A PE FILE` / risk
`0`, which is the opposite of what a "malware detection" tool should do with
the one file every real antivirus product is required to catch.

- **`backend/signatures.py`** (new) — a signature-detection layer that runs
  on every file *before* PE parsing: substring match for the EICAR test
  string (how every commercial AV detects it), plus a small SHA-256
  blocklist as defense-in-depth. Extend `KNOWN_HASHES` there as a starting
  point for a real known-malware hash feed.
- **`backend/scorer.py`** — added `score_signature_match()`: a signature hit
  is reported as `MALICIOUS` / risk `100`, independent of the heuristic
  weighting used for PE structural analysis.
- **`backend/main.py`** — ZIP handling was rewritten:
  - Every file *inside* the archive is now signature-scanned, not just
    probed as a PE and shrugged off if it isn't one. This is the actual fix
    for "the EICAR zip doesn't work."
  - One level of nested ZIPs (a `.zip` inside a `.zip`) is followed.
  - **ZIP-bomb protection**: each entry is decompressed in bounded chunks
    with a hard cap enforced against bytes actually produced (not just the
    archive's self-reported, spoofable size), plus a per-entry cap, an
    aggregate-across-the-archive cap, and a total entry-count cap.
  - Password-protected / corrupt entries are now skipped gracefully with a
    clear note instead of the request failing.
  - CORS is now controlled by `SCANFORGE_ALLOWED_ORIGINS` (defaults to `*`
    with a logged warning — set it before deploying anywhere untrusted).
  - A catch-all exception handler logs unhandled errors server-side and
    returns a clean, non-leaky 500 to the client.
  - Structured logging of every scan (filename, hash, verdict — never file
    content) for an audit trail.
- **EICAR demo sample** — a fourth one-click "Try a sample" button on the
  frontend serves the EICAR test file. It is generated **in-memory at
  request time** (see `IN_MEMORY_SAMPLES` in `main.py`), never written to
  disk — an on-disk `eicar.com` gets quarantined by the host's own
  antivirus (Windows Defender included), which would break the demo on
  exactly the machines it runs on.
- **`backend/tests/`** (new) — pytest suite covering signature detection and
  the ZIP edge cases above (EICAR raw/zipped/nested, zip bombs, too many
  entries, password-protected, empty, misnamed-non-zip, benign PE, the
  original three samples). 22 tests, all passing.
- **Dockerfile** — runs as a non-root user, adds a `HEALTHCHECK`, still
  builds the synthetic PE samples at image build time.
- **docker-compose.yml** — added a healthcheck and environment passthrough
  for `SCANFORGE_ALLOWED_ORIGINS` / `LOG_LEVEL`.

## Running locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python samples/generate_samples.py
uvicorn main:app --reload
```

Open `frontend/index.html` directly, or visit `http://localhost:8000/app/`
(the backend serves the frontend statically).

## Running the tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest -v
```

## Running with Docker

```bash
docker compose up --build
```

Set `SCANFORGE_ALLOWED_ORIGINS` in your environment (or a `.env` file next
to `docker-compose.yml`) before exposing this anywhere other than
`localhost` — it defaults to allowing every origin, which is fine for a demo
and wrong for anything else.

## Known limitations (be aware, not blockers)

- Detection is signature + PE-heuristic based, not a full AV engine — it
  will not catch novel malware with no matching signature and no PE
  structural red flags. That's inherent to the static-analysis approach
  this app takes (see the "polymorphic detection" note below), not a bug.
- ZIP nesting is followed one level deep; a `.zip` inside a `.zip` inside a
  `.zip` is reported as an oversized/complex archive rather than fully
  unwrapped, which is a deliberate trade-off against zip-bomb-by-nesting
  attacks.
- The three synthetic `.exe` samples are hand-built structural stubs for
  demo purposes, not real-world binaries — expect real executables to show
  more varied entropy/import patterns than the samples do.

## On "polymorphic malware detection"

This project's stated goal is broader than what ships here today. What's in
place now is signature matching (catches known-exact threats like EICAR) and
static PE heuristics (entropy, suspicious imports, entry-point placement —
catches *some* packed/obfuscated binaries generically). True polymorphic
detection — recognising a *mutating* family across many differently-packed
variants — generally needs one or more of: fuzzy/structural hashing
(ssdeep/TLSH) to cluster near-identical variants despite byte-level changes,
YARA-style rule matching on decrypted/emulated code rather than raw bytes,
or a trained classifier over the feature set `analyzer.py` already extracts.
None of that is implemented yet; the signature layer added here is the
prerequisite piece it would sit next to, not a replacement for it.
