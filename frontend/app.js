/**
 * app.js — ScanForge frontend logic.
 *
 * Handles:
 *  - Drag-and-drop + click-to-browse file upload
 *  - Pre-loaded sample button clicks (GET /sample/{name})
 *  - POST /analyze for user-uploaded files
 *  - Rendering results: verdict pill, score ring, stat grid, factor bars, API chips
 *  - Score ring animation (0 → final over 650ms)
 *  - Loading spinner + error state
 */

"use strict";

const API_BASE = window.location.protocol === "file:"
  ? "http://localhost:8000"
  : (window.location.port === "8000" ? "" : "http://localhost:8000");


// ── DOM refs ──────────────────────────────────────────────────────────────────
const dropZone      = document.getElementById("drop-zone");
const fileInput     = document.getElementById("file-input");
const browseBtn     = document.getElementById("browse-btn");
const loadingState  = document.getElementById("loading-state");
const errorState    = document.getElementById("error-state");
const errorMessage  = document.getElementById("error-message");
const resultsPanel  = document.getElementById("results-panel");

// Results fields
const scoreNumber   = document.getElementById("score-number");
const ringFill      = document.getElementById("ring-fill");
const verdictPill   = document.getElementById("verdict-pill");
const verdictMeta   = document.getElementById("verdict-meta");
const filenameEl    = document.getElementById("result-filename");
const statSha       = document.getElementById("stat-sha256");
const statSize      = document.getElementById("stat-size");
const statSections  = document.getElementById("stat-sections");
const statEntropy   = document.getElementById("stat-entropy");
const apiSection    = document.getElementById("api-section");
const apiChips      = document.getElementById("api-chips");
const factorsList   = document.getElementById("factors-list");
const factorsSection = document.getElementById("factors-section");
const parseNote     = document.getElementById("parse-note");
const parseNoteText = document.getElementById("parse-note-text");

// ── Ring geometry ─────────────────────────────────────────────────────────────
// SVG circle: r=42, so circumference = 2π×42 ≈ 263.89
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

// ── UI state helpers ──────────────────────────────────────────────────────────

function showLoading() {
  loadingState.classList.add("visible");
  errorState.classList.remove("visible");
  resultsPanel.classList.remove("visible");
  resultsPanel.style.display = "none";
}

function showError(msg) {
  loadingState.classList.remove("visible");
  errorState.classList.add("visible");
  errorMessage.textContent = msg;
  resultsPanel.classList.remove("visible");
  resultsPanel.style.display = "none";
}

function hideTransient() {
  loadingState.classList.remove("visible");
  errorState.classList.remove("visible");
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
    // Ease-out cubic
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

  // Parse-note banner (non-PE files)
  if (data.not_pe && data.parse_note) {
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

  // Show results panel, then animate
  resultsPanel.style.display = "block";
  // Force reflow so transition fires
  void resultsPanel.offsetHeight;
  resultsPanel.classList.add("visible");

  // Animate ring (skip for non-PE files — score is always 0)
  if (!data.not_pe) {
    setTimeout(() => animateRing(data.risk_score), 50);
  } else {
    scoreNumber.textContent = "—";
    scoreNumber.style.color = "var(--text-muted)";
    ringFill.style.stroke = "var(--border)";
    ringFill.style.strokeDashoffset = RING_CIRCUMFERENCE;
  }

  // Animate factor bars (staggered)
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

// ── HTML escape ───────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── API calls ─────────────────────────────────────────────────────────────────

async function analyzeFile(file) {
  showLoading();
  const form = new FormData();
  form.append("file", file);

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      body: form,
    });
    const json = await res.json();
    if (!res.ok) {
      showError(json.detail ?? `Server error (${res.status})`);
      return;
    }
    renderResult(json);
  } catch (err) {
    showError(`Could not reach the ScanForge backend at ${API_BASE}. Is it running? (${err.message})`);
  }
}

async function analyzeSample(name) {
  showLoading();
  try {
    const res = await fetch(`${API_BASE}/sample/${encodeURIComponent(name)}`);
    const json = await res.json();
    if (!res.ok) {
      showError(json.detail ?? `Server error (${res.status})`);
      return;
    }
    renderResult(json);
  } catch (err) {
    showError(`Could not reach the ScanForge backend at ${API_BASE}. Is it running? (${err.message})`);
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
    fileInput.value = "";    // reset so same file can be re-selected
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
