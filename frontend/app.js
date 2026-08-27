/**
 * app.js — ScanForge frontend logic.
 *
 * Handles:
 *  - Drag-and-drop + click-to-browse file upload
 *  - Pre-loaded sample button clicks
 *  - Step-by-step SSE pipeline streaming (/analyze/stream & /sample/{name}/stream)
 *  - Rendering results: verdict pill, score ring, stat grid, factor bars, API chips
 *  - Animated pipeline progress panel
 */

"use strict";

const API_BASE = window.location.protocol === "file:"
  ? "http://localhost:8000"
  : (window.location.port === "8000" ? "" : "http://localhost:8000");


// ── DOM refs ──────────────────────────────────────────────────────────────────
const dropZone        = document.getElementById("drop-zone");
const fileInput       = document.getElementById("file-input");
const browseBtn       = document.getElementById("browse-btn");
const pipelinePanel   = document.getElementById("pipeline-panel");
const pipelineSpinner = document.getElementById("pipeline-spinner");
const pipelineSteps   = document.getElementById("pipeline-steps");
const errorState      = document.getElementById("error-state");
const errorMessage    = document.getElementById("error-message");
const resultsPanel    = document.getElementById("results-panel");

// Results fields
const scoreNumber     = document.getElementById("score-number");
const ringFill        = document.getElementById("ring-fill");
const verdictPill     = document.getElementById("verdict-pill");
const verdictMeta     = document.getElementById("verdict-meta");
const filenameEl      = document.getElementById("result-filename");
const statSha         = document.getElementById("stat-sha256");
const statSize        = document.getElementById("stat-size");
const statSections    = document.getElementById("stat-sections");
const statEntropy     = document.getElementById("stat-entropy");
const apiSection      = document.getElementById("api-section");
const apiChips        = document.getElementById("api-chips");
const factorsList     = document.getElementById("factors-list");
const factorsSection  = document.getElementById("factors-section");
const parseNote       = document.getElementById("parse-note");
const parseNoteText   = document.getElementById("parse-note-text");

// ── Ring geometry ─────────────────────────────────────────────────────────────
const RING_CIRCUMFERENCE = 2 * Math.PI * 42;

// ── Utility ───────────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 * 1024)  return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function truncateSha(sha) {
  return sha ? `${sha.slice(0, 8)}…${sha.slice(-8)}` : "—";
}

function verdictClass(verdict) {
  return {
    BENIGN:         "benign",
    SUSPICIOUS:     "suspicious",
    MALICIOUS:      "malicious",
    "NOT A PE FILE": "not-pe",
  }[verdict] ?? "not-pe";
}

function ringColor(score) {
  if (score < 25)  return "var(--color-benign)";
  if (score < 50)  return "var(--color-suspicious)";
  return "var(--color-malicious)";
}

function barColorClass(weight) {
  if (weight <= 12) return "bar-low";
  if (weight <= 20) return "bar-mid";
  return "bar-high";
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── UI state helpers ──────────────────────────────────────────────────────────

function resetPipelineUI() {
  pipelineSteps.innerHTML = "";
  pipelineSpinner.classList.remove("done");
  pipelinePanel.classList.add("visible");
  errorState.classList.remove("visible");
  resultsPanel.classList.remove("visible");
  resultsPanel.style.display = "none";
}

function finishPipelineUI() {
  pipelineSpinner.classList.add("done");
}

function showError(msg) {
  pipelinePanel.classList.remove("visible");
  errorState.classList.add("visible");
  errorMessage.textContent = msg;
  resultsPanel.classList.remove("visible");
  resultsPanel.style.display = "none";
}

function hideTransient() {
  errorState.classList.remove("visible");
}

// ── Step card builder ─────────────────────────────────────────────────────────

function addPipelineStep(icon, label, value, badgeText, badgeClass) {
  const stepEl = document.createElement("div");
  stepEl.className = "pipeline-step";
  stepEl.innerHTML = `
    <div class="step-icon" aria-hidden="true">${icon}</div>
    <div class="step-body">
      <div class="step-label">${escHtml(label)}</div>
      <div class="step-value">${escHtml(value)}</div>
    </div>
    ${badgeText ? `<span class="step-badge ${badgeClass}">${escHtml(badgeText)}</span>` : ""}
  `;
  pipelineSteps.appendChild(stepEl);
  void stepEl.offsetHeight; // Force reflow
  stepEl.classList.add("visible");

  // Auto-scroll step into view
  stepEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── Event dispatch per pipeline SSE event ─────────────────────────────────────

function handlePipelineEvent(data) {
  switch (data.step) {
    case "received":
      addPipelineStep(
        "📥",
        "1. File Ingestion",
        `Received '${data.filename}' (${formatBytes(data.size)})`,
        "Ingested",
        "neutral"
      );
      break;

    case "zip_extract":
      if (data.ok === false) {
        addPipelineStep(
          "📦",
          "2. ZIP Extraction",
          `Decompression failed: ${data.error}`,
          "Rejected",
          "bad"
        );
      } else {
        const details = data.files ? `Extracted files: ${data.files.join(", ")}` : `Extracted target from archive`;
        addPipelineStep(
          "📦",
          "2. ZIP Decompression",
          details,
          "Unpacked",
          "ok"
        );
      }
      break;

    case "hashing":
      addPipelineStep(
        "🔑",
        "3. SHA-256 Hashing",
        `SHA-256: ${data.sha256}`,
        "Hashed",
        "neutral"
      );
      break;

    case "hash_check":
      if (data.matched) {
        addPipelineStep(
          "🚨",
          "4. Known-Hash Blocklist Check",
          `Exact hash match: ${data.name} — verdict pinned to MALICIOUS`,
          "Hash Match",
          "bad"
        );
      } else {
        addPipelineStep(
          "🗂️",
          "4. Known-Hash Blocklist Check",
          "No match in the known-hash blocklist — continuing structural analysis",
          "No Match",
          "ok"
        );
      }
      break;

    case "pe_parse":
      if (data.ok) {
        addPipelineStep(
          "🧩",
          "5. PE Structure Parsing",
          `MZ/PE header valid · ${data.num_sections} section(s) discovered`,
          "Valid PE",
          "ok"
        );
      } else {
        addPipelineStep(
          "🧩",
          "5. PE Structure Parsing",
          data.error || "No valid PE/MZ header present",
          "Not a PE",
          "neutral"
        );
      }
      break;

    case "entropy":
      {
        const maxVal = data.max;
        const badge = maxVal > 7.2 ? "High (High Risk)" : (maxVal > 6.5 ? "Elevated" : "Normal");
        const bClass = maxVal > 7.2 ? "bad" : (maxVal > 6.5 ? "warn" : "ok");
        addPipelineStep(
          "📊",
          "6. Shannon Entropy Calculation",
          `Avg section entropy: ${data.avg.toFixed(2)} bits/byte · Max section entropy: ${maxVal.toFixed(2)} bits/byte`,
          badge,
          bClass
        );
      }
      break;

    case "imports":
      {
        const count = data.suspicious ? data.suspicious.length : 0;
        const text = count > 0
          ? `Total imports: ${data.total} · Flagged APIs: ${data.suspicious.join(", ")}`
          : `Total imports: ${data.total} · No high-risk injection/evasion APIs flagged`;
        const badge = count > 0 ? `${count} Flagged API(s)` : "Clean";
        const bClass = count > 0 ? "bad" : "ok";
        addPipelineStep(
          "⚙️",
          "7. Import Table Scan",
          text,
          badge,
          bClass
        );
      }
      break;

    case "ep_check":
      {
        const text = data.outside_text
          ? "Entry point is outside the primary .text code section (packers/loaders pattern)"
          : "Entry point is inside the standard .text code section";
        const badge = data.outside_text ? "EP Anomaly" : "Standard EP";
        const bClass = data.outside_text ? "warn" : "ok";
        addPipelineStep(
          "📍",
          "8. Entry Point Location Check",
          text,
          badge,
          bClass
        );
      }
      break;

    case "scoring":
      {
        const bClass = data.verdict === "MALICIOUS" ? "bad" : (data.verdict === "SUSPICIOUS" ? "warn" : "ok");
        addPipelineStep(
          "⚖️",
          "9. Heuristic Risk Scoring & Verdict",
          `Score: ${data.risk_score}/100 · Verdict: ${data.verdict} (${data.factors.length} weighted factor(s) triggered)`,
          data.verdict,
          bClass
        );
      }
      break;
  }
}

// ── Score ring animation ──────────────────────────────────────────────────────

let ringAnimFrame = null;

function animateRing(targetScore) {
  if (ringAnimFrame) cancelAnimationFrame(ringAnimFrame);

  const color    = ringColor(targetScore);
  const duration = 650; // ms
  const start    = performance.now();

  ringFill.style.stroke = color;
  scoreNumber.style.color = color;

  function step(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const current  = eased * targetScore;

    scoreNumber.textContent = Math.round(current);
    const offset = RING_CIRCUMFERENCE * (1 - current / 100);
    ringFill.style.strokeDashoffset = offset;

    if (progress < 1) {
      ringAnimFrame = requestAnimationFrame(step);
    } else {
      scoreNumber.textContent = Math.round(targetScore);
    }
  }

  requestAnimationFrame(step);
}

// ── Render result ─────────────────────────────────────────────────────────────

function renderResult(data) {
  hideTransient();

  // Parse-note banner (non-PE files, incl. hash hits on non-PE content)
  if (data.parse_note) {
    parseNoteText.textContent = data.parse_note;
    parseNote.classList.add("visible");
  } else {
    parseNote.classList.remove("visible");
    parseNoteText.textContent = "";
  }

  // Filename
  filenameEl.textContent = data.filename;

  // Verdict pill
  const cls = verdictClass(data.verdict);
  verdictPill.className = `verdict-pill ${cls}`;
  verdictPill.innerHTML = `<span class="verdict-pill-dot"></span>${data.verdict}`;

  // Verdict meta
  verdictMeta.textContent = data.not_pe
    ? `SHA-256 · ${formatBytes(data.file_size)} · raw entropy ${data.avg_section_entropy.toFixed(2)} bits`
    : `Risk score ${data.risk_score}/100 · ${data.factors.length} signal${data.factors.length !== 1 ? "s" : ""} triggered`;

  // Archive note (zip extraction)
  let archiveNoteEl = document.getElementById("archive-note");
  if (data.archive_note) {
    if (!archiveNoteEl) {
      archiveNoteEl = document.createElement("p");
      archiveNoteEl.id = "archive-note";
      archiveNoteEl.style.cssText = "font-size:0.75rem;color:var(--text-muted);margin-top:4px;";
      verdictMeta.parentNode.insertBefore(archiveNoteEl, verdictMeta.nextSibling);
    }
    archiveNoteEl.textContent = data.archive_note;
  } else if (archiveNoteEl) {
    archiveNoteEl.textContent = "";
  }

  // Stats
  statSha.textContent      = truncateSha(data.sha256);
  statSha.title            = data.sha256;
  statSize.textContent     = formatBytes(data.file_size);
  statSections.textContent = data.num_sections;
  statEntropy.textContent  = `${data.avg_section_entropy.toFixed(2)} bits`;

  // Suspicious APIs
  if (data.suspicious_apis_found && data.suspicious_apis_found.length > 0) {
    apiSection.classList.add("visible");
    apiChips.innerHTML = data.suspicious_apis_found
      .map(api => `<span class="api-chip" title="${api}">${api}</span>`)
      .join("");
  } else {
    apiSection.classList.remove("visible");
    apiChips.innerHTML = "";
  }

  // Risk factors
  if (data.factors && data.factors.length > 0) {
    factorsList.innerHTML = data.factors.map(f => {
      const pct   = Math.min((f.weight / 100) * 100, 100);
      const color = barColorClass(f.weight);
      return `
        <div class="factor-row">
          <div class="factor-header">
            <span class="factor-label">${escHtml(f.label)}</span>
            <span class="factor-weight">+${f.weight} pts</span>
          </div>
          <div class="factor-bar-track">
            <div class="factor-bar-fill ${color}" data-pct="${pct}"></div>
          </div>
          <p class="factor-detail">${escHtml(f.detail)}</p>
        </div>
      `;
    }).join("");
  } else {
    factorsList.innerHTML = data.not_pe
      ? `<p class="no-factors">Not a PE file — structural analysis skipped.</p>`
      : `<p class="no-factors">No risk signals triggered — file appears structurally normal.</p>`;
  }

  // Show results panel
  resultsPanel.style.display = "block";
  void resultsPanel.offsetHeight;
  resultsPanel.classList.add("visible");

  // Ring styling / animation
  if (!data.not_pe) {
    setTimeout(() => animateRing(data.risk_score), 50);
  } else {
    scoreNumber.textContent = "—";
    scoreNumber.style.color = "var(--text-muted)";
    ringFill.style.stroke = "var(--border)";
    ringFill.style.strokeDashoffset = RING_CIRCUMFERENCE;
  }

  // Animate factor bars
  const fills = factorsList.querySelectorAll(".factor-bar-fill");
  fills.forEach((el, i) => {
    setTimeout(() => {
      el.style.width = el.dataset.pct + "%";
    }, 120 + i * 60);
  });

  // Scroll to results
  setTimeout(() => {
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, 100);
}

// ── SSE Stream Reader Helper ──────────────────────────────────────────────────

async function readSseStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n\n");
    buffer = lines.pop(); // keep partial trailing buffer

    for (const block of lines) {
      const line = block.trim();
      if (line.startsWith("data: ")) {
        try {
          const payload = JSON.parse(line.slice(6));
          if (payload.step === "complete") {
            finishPipelineUI();
            renderResult(payload.result);
          } else {
            handlePipelineEvent(payload);
          }
        } catch (e) {
          console.error("Failed to parse SSE payload", e, line);
        }
      }
    }
  }

  // Flush remaining buffer if any
  if (buffer.trim().startsWith("data: ")) {
    try {
      const payload = JSON.parse(buffer.trim().slice(6));
      if (payload.step === "complete") {
        finishPipelineUI();
        renderResult(payload.result);
      } else {
        handlePipelineEvent(payload);
      }
    } catch (e) {
      // ignore
    }
  }
}

// ── API calls ─────────────────────────────────────────────────────────────────

async function analyzeFile(file) {
  resetPipelineUI();

  let buf;
  try {
    buf = await file.arrayBuffer();
  } catch (err) {
    showError(`Could not read '${file.name}' from disk: ${err.message}`);
    return;
  }

  const form = new FormData();
  form.append("file", new Blob([buf]), file.name);

  try {
    const res = await fetch(`${API_BASE}/analyze/stream`, {
      method: "POST",
      body: form,
      cache: "no-store",
    });

    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      showError(json.detail ?? `Server error (${res.status})`);
      return;
    }

    await readSseStream(res);
  } catch (err) {
    showError(`Could not reach ScanForge backend at ${API_BASE || window.location.origin}. Is it running? (${err.message})`);
  }
}

async function analyzeSample(name) {
  resetPipelineUI();
  try {
    const res = await fetch(`${API_BASE}/sample/${encodeURIComponent(name)}/stream`, {
      cache: "no-store",
    });

    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      showError(json.detail ?? `Server error (${res.status})`);
      return;
    }

    await readSseStream(res);
  } catch (err) {
    showError(`Could not reach ScanForge backend at ${API_BASE}. Is it running? (${err.message})`);
  }
}

// ── Event: browse button ──────────────────────────────────────────────────────

browseBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  fileInput.click();
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) {
    analyzeFile(fileInput.files[0]);
    fileInput.value = "";
  }
});

// ── Event: drop zone click ────────────────────────────────────────────────────

dropZone.addEventListener("click", (e) => {
  if (e.target === browseBtn || browseBtn.contains(e.target)) return;
  fileInput.click();
});

// ── Event: drag and drop ──────────────────────────────────────────────────────

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", (e) => {
  if (!dropZone.contains(e.relatedTarget)) {
    dropZone.classList.remove("drag-over");
  }
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  const files = e.dataTransfer.files;
  if (files.length > 0) {
    analyzeFile(files[0]);
  }
});

// ── Event: sample buttons ─────────────────────────────────────────────────────

document.querySelectorAll(".sample-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const name = btn.dataset.sample;
    if (name) analyzeSample(name);
  });
});
