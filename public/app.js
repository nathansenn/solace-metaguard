// ---------------------------------------------------------------------------
// GuardianScan v2.0 — Frontend
// House of Senn · Built by Solace
// ---------------------------------------------------------------------------

// ---- DOM refs ----
const analyzeForm = document.getElementById("analyze-form");
const promptForm = document.getElementById("prompt-form");
const fileInput = document.getElementById("file-input");
const extraText = document.getElementById("extra-text");
const promptText = document.getElementById("prompt-text");
const analyzeBtn = document.getElementById("analyze-btn");
const promptBtn = document.getElementById("prompt-btn");
const resultsEl = document.getElementById("results");
const statusLine = document.getElementById("status");
const modeBanner = document.getElementById("mode-banner");
const dropZone = document.getElementById("drop-zone");
const filePreview = document.getElementById("file-preview");
const toastContainer = document.getElementById("toast-container");

// ---- Tabs ----
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab)?.classList.add("active");
  });
});

// ---- Toast ----
function showToast(message, icon = "\u2705") {
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<span>${icon}</span> ${escapeHtml(message)}`;
  toastContainer.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 250);
  }, 2500);
}

// ---- Helpers ----
function setStatus(message, isError = false) {
  if (isError) {
    statusLine.textContent = message;
    statusLine.className = "status error";
  } else if (message.includes("...")) {
    statusLine.innerHTML = `<span class="spinner"></span>${escapeHtml(message)}`;
    statusLine.className = "status muted";
  } else {
    statusLine.textContent = message;
    statusLine.className = "status muted";
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function badge(level) {
  const safe = escapeHtml(String(level || "low"));
  return `<span class="badge ${safe}">${safe}</span>`;
}

function chevronSvg() {
  return `<svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>`;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => showToast("Copied to clipboard", "\u{1F4CB}"),
    () => showToast("Copy failed", "\u274C")
  );
}

function scoreBar(score, level) {
  return `
    <div class="score-bar-wrap">
      <div class="score-bar-labels">
        <span>Injection Score</span>
        <span class="score-val">${score}/100</span>
      </div>
      <div class="score-bar">
        <div class="score-bar-fill ${level}" style="width: ${Math.max(2, score)}%"></div>
      </div>
    </div>
  `;
}

function collapsibleCard(id, iconClass, icon, title, badgeHtml, bodyHtml, startOpen = true) {
  const collapsed = startOpen ? "" : " collapsed";
  return `
    <article class="card${collapsed}" id="card-${id}">
      <div class="card-header" onclick="document.getElementById('card-${id}').classList.toggle('collapsed')">
        <div class="card-header-left">
          <div class="card-icon ${iconClass}">${icon}</div>
          <span class="card-title">${title}</span>
        </div>
        <div class="card-header-right">
          ${badgeHtml}
          ${chevronSvg()}
        </div>
      </div>
      <div class="card-body">
        ${bodyHtml}
      </div>
    </article>
  `;
}

// ---- Drag & Drop ----
["dragenter", "dragover"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
});

["dragleave", "drop"].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
  });
});

dropZone.addEventListener("drop", (e) => {
  const files = e.dataTransfer?.files;
  if (files?.length) {
    fileInput.files = files;
    updateFilePreview();
  }
});

// ---- File Preview ----
fileInput.addEventListener("change", updateFilePreview);

function updateFilePreview() {
  const file = fileInput.files?.[0];
  if (!file) {
    filePreview.classList.add("hidden");
    filePreview.innerHTML = "";
    return;
  }
  filePreview.classList.remove("hidden");
  filePreview.innerHTML = `
    <span class="file-name">${escapeHtml(file.name)}</span>
    <span class="file-size">${formatBytes(file.size)}</span>
    <button type="button" class="file-remove" title="Remove file">&times;</button>
  `;
  filePreview.querySelector(".file-remove").addEventListener("click", () => {
    fileInput.value = "";
    filePreview.classList.add("hidden");
    filePreview.innerHTML = "";
  });
}

// ---- Render: Full File Analysis ----
function renderAnalysis(payload) {
  const file = payload.file || {};
  const metadata = payload.metadata || {};
  const virusScan = payload.virusScan || {};
  const pi = payload.promptInjection || {};

  const cards = [];

  // 1. File Summary
  const sha = escapeHtml(file.sha256 || "n/a");
  const fileBody = `
    <ul class="kv-list">
      <li><strong>Name</strong> <span>${escapeHtml(file.name || "Unknown")}</span></li>
      <li><strong>Type</strong> <span>${escapeHtml(file.kind || "unknown")} (${escapeHtml(file.mimeType || "unknown")})</span></li>
      <li><strong>Size</strong> <span>${formatBytes(file.sizeBytes)}</span></li>
      <li><strong>SHA-256</strong> <span class="kv-value mono clickable" onclick="copyToClipboard('${sha}')" title="Click to copy">${sha}</span>
        <button class="copy-btn" onclick="event.stopPropagation(); copyToClipboard('${sha}')">Copy</button>
      </li>
    </ul>
  `;
  cards.push(collapsibleCard("file", "file", "\u{1F4C4}", "File Summary", badge("info"), fileBody));

  // 2. Prompt Injection
  const matchCount = (pi.matches?.length || 0) + (pi.base64Findings?.length || 0);
  let piBody = scoreBar(pi.score || 0, pi.riskLevel || "low");
  piBody += `
    <ul class="kv-list">
      <li><strong>Rules</strong> <span>${pi.rulesCount || 30} active patterns</span></li>
      <li><strong>Matches</strong> <span>${matchCount}</span></li>
      <li><strong>Summary</strong> <span>${escapeHtml(pi.summary || "No result")}</span></li>
    </ul>
  `;

  if (pi.filenameWarnings?.length) {
    piBody += `<ul class="notes-list">`;
    for (const w of pi.filenameWarnings) {
      piBody += `<li class="warning">${escapeHtml(w)}</li>`;
    }
    piBody += `</ul>`;
  }

  if (pi.matches?.length || pi.base64Findings?.length) {
    piBody += `<div class="match-list">`;
    for (const m of (pi.matches || [])) {
      piBody += `
        <div class="match-item">
          <div class="match-header">
            <span class="match-id">${escapeHtml(m.id)}</span>
            <span class="match-weight">+${m.weight}</span>
          </div>
          <div class="match-label">${escapeHtml(m.label)}</div>
          <div class="match-excerpt">${escapeHtml(m.excerpt || "")}</div>
        </div>
      `;
    }
    for (const m of (pi.base64Findings || [])) {
      piBody += `
        <div class="match-item base64">
          <div class="match-header">
            <span class="match-id">${escapeHtml(m.id)}</span>
            <span class="match-weight">+${m.weight}</span>
          </div>
          <div class="match-label">${escapeHtml(m.label)}</div>
          <div class="match-excerpt">${escapeHtml(m.excerpt || "")}</div>
        </div>
      `;
    }
    piBody += `</div>`;
  }

  cards.push(collapsibleCard("injection", "injection", "\u{1F6E1}", "Prompt Injection", badge(pi.riskLevel || "low"), piBody));

  // 3. Virus Scan
  const vsLocal = virusScan.local || {};
  const vsVt = virusScan.virustotal || {};
  const overallBadge = virusScan.overallStatus === "malicious" ? "malicious"
    : virusScan.overallStatus === "suspicious" ? "suspicious"
    : "clean";

  let vsBody = `
    <ul class="kv-list">
      <li><strong>Overall</strong> ${badge(overallBadge)}</li>
      <li><strong>Local Engine</strong> <span>${escapeHtml(vsLocal.status || "n/a")}</span></li>
      <li><strong>VirusTotal</strong> <span>${escapeHtml(vsVt.status || "n/a")}</span></li>
    </ul>
  `;

  // Local findings
  if (vsLocal.findings?.length) {
    vsBody += `<div class="match-list">`;
    for (const f of vsLocal.findings) {
      vsBody += `
        <div class="match-item ${f.severity === "malicious" ? "base64" : ""}">
          <div class="match-label">${escapeHtml(f.label)}</div>
          <div class="match-excerpt">${escapeHtml(f.detail || "")}</div>
        </div>
      `;
    }
    vsBody += `</div>`;
  }

  // VirusTotal detailed results
  if (vsVt.status === "completed") {
    vsBody += `
      <div class="stats-row">
        <div class="stat-box ${vsVt.malicious > 0 ? "danger" : "safe"}">
          <div class="stat-value">${vsVt.malicious}</div>
          <div class="stat-label">Malicious</div>
        </div>
        <div class="stat-box ${vsVt.suspicious > 0 ? "warn" : "safe"}">
          <div class="stat-value">${vsVt.suspicious}</div>
          <div class="stat-label">Suspicious</div>
        </div>
        <div class="stat-box safe">
          <div class="stat-value">${vsVt.harmless}</div>
          <div class="stat-label">Harmless</div>
        </div>
        <div class="stat-box info">
          <div class="stat-value">${vsVt.undetected}</div>
          <div class="stat-label">Undetected</div>
        </div>
        <div class="stat-box info">
          <div class="stat-value">${vsVt.totalEngines || 0}</div>
          <div class="stat-label">Total</div>
        </div>
      </div>
    `;

    if (vsVt.meaningfulName || vsVt.typeDescription) {
      vsBody += `
        <ul class="kv-list">
          ${vsVt.meaningfulName ? `<li><strong>Name</strong> <span>${escapeHtml(vsVt.meaningfulName)}</span></li>` : ""}
          ${vsVt.typeDescription ? `<li><strong>Type</strong> <span>${escapeHtml(vsVt.typeDescription)}</span></li>` : ""}
          ${vsVt.scannedAt ? `<li><strong>Scanned</strong> <span>${escapeHtml(vsVt.scannedAt)}</span></li>` : ""}
          ${vsVt.communityScore != null ? `<li><strong>Community Score</strong> <span>${vsVt.communityScore}</span></li>` : ""}
        </ul>
      `;
    }

    // Engine breakdown
    if (vsVt.detectedEngines?.length) {
      vsBody += `<div class="engine-list">`;
      for (const e of vsVt.detectedEngines) {
        vsBody += `
          <div class="engine-item">
            <span class="engine-name">${escapeHtml(e.engine)}</span>
            <span class="engine-result">${escapeHtml(e.result)}</span>
          </div>
        `;
      }
      vsBody += `</div>`;
    }

    // Permalink
    if (vsVt.permalink) {
      vsBody += `<a class="vt-link" href="${escapeHtml(vsVt.permalink)}" target="_blank" rel="noopener">
        \u{1F517} View on VirusTotal
      </a>`;
    }
  } else if (vsVt.status === "not_configured") {
    vsBody += `
      <div class="vt-config">
        <span>\u26A0\uFE0F</span>
        <div>
          VirusTotal is not configured. To enable cloud-based malware intelligence:<br>
          1. Get a free API key at <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener">virustotal.com</a><br>
          2. Set the environment variable: <code>VIRUSTOTAL_API_KEY=your_key_here</code><br>
          3. Restart the server.
        </div>
      </div>
    `;
  } else if (vsVt.status === "rate_limited") {
    vsBody += `
      <div class="vt-config">
        <span>\u23F3</span>
        <div>${escapeHtml(vsVt.message || "Rate limited. Free tier allows 4 requests/minute.")}</div>
      </div>
    `;
  } else if (vsVt.status === "queued") {
    vsBody += `
      <div class="vt-config">
        <span>\u{1F504}</span>
        <div>${escapeHtml(vsVt.message || "Analysis still pending on VirusTotal.")}</div>
      </div>
    `;
  } else if (vsVt.status === "error") {
    vsBody += `
      <div class="vt-config">
        <span>\u274C</span>
        <div>${escapeHtml(vsVt.message || "VirusTotal request failed.")}</div>
      </div>
    `;
  }

  cards.push(collapsibleCard("virus", "virus", "\u{1F41B}", "Virus Scan", badge(overallBadge), vsBody));

  // 4. Metadata
  const details = metadata.details || {};
  const notes = metadata.notes || [];
  let metaBody = "";

  if (Object.keys(details).length > 0) {
    metaBody += `<pre class="code-block">${escapeHtml(JSON.stringify(details, null, 2))}</pre>`;
  } else {
    metaBody += `<p style="color: var(--muted); font-size: 0.82rem;">No metadata extracted.</p>`;
  }

  if (notes.length > 0) {
    metaBody += `<ul class="notes-list">`;
    for (const n of notes) {
      const isWarn = /warning|xss|phishing|macro/i.test(n);
      metaBody += `<li class="${isWarn ? "warning" : ""}">${escapeHtml(n)}</li>`;
    }
    metaBody += `</ul>`;
  }

  cards.push(collapsibleCard("metadata", "metadata", "\u{1F4DD}", "Metadata", "", metaBody, false));

  // 5. Text Preview
  const preview = payload.extractedTextPreview || "";
  let previewBody = "";
  if (preview) {
    previewBody = `<pre class="code-block">${escapeHtml(preview)}</pre>`;
  } else {
    previewBody = `<p style="color: var(--muted); font-size: 0.82rem;">No text extracted from this file.</p>`;
  }

  cards.push(collapsibleCard("textprev", "text-preview", "\u{1F4C3}", "Extracted Text", "", previewBody, false));

  resultsEl.innerHTML = cards.join("\n");
}

// ---- Render: Prompt Scan Only ----
function renderPromptOnly(payload) {
  const pi = payload.promptInjection || {};
  const matchCount = (pi.matches?.length || 0) + (pi.base64Findings?.length || 0);

  let body = scoreBar(pi.score || 0, pi.riskLevel || "low");
  body += `
    <ul class="kv-list">
      <li><strong>Rules</strong> <span>${pi.rulesCount || 30} active patterns</span></li>
      <li><strong>Matches</strong> <span>${matchCount}</span></li>
      <li><strong>Summary</strong> <span>${escapeHtml(pi.summary || "No result")}</span></li>
    </ul>
  `;

  if (pi.matches?.length || pi.base64Findings?.length) {
    body += `<div class="match-list">`;
    for (const m of (pi.matches || [])) {
      body += `
        <div class="match-item">
          <div class="match-header">
            <span class="match-id">${escapeHtml(m.id)}</span>
            <span class="match-weight">+${m.weight}</span>
          </div>
          <div class="match-label">${escapeHtml(m.label)}</div>
          <div class="match-excerpt">${escapeHtml(m.excerpt || "")}</div>
        </div>
      `;
    }
    for (const m of (pi.base64Findings || [])) {
      body += `
        <div class="match-item base64">
          <div class="match-header">
            <span class="match-id">${escapeHtml(m.id)}</span>
            <span class="match-weight">+${m.weight}</span>
          </div>
          <div class="match-label">${escapeHtml(m.label)}</div>
          <div class="match-excerpt">${escapeHtml(m.excerpt || "")}</div>
        </div>
      `;
    }
    body += `</div>`;
  }

  resultsEl.innerHTML = collapsibleCard("injection", "injection", "\u{1F6E1}", "Prompt Injection Scan", badge(pi.riskLevel || "low"), body);
}

// ---- File Analysis Submit ----
analyzeForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!fileInput.files?.length) {
    setStatus("Choose a file first.", true);
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = `<span class="spinner"></span> Analyzing...`;
  setStatus("Running full analysis...");

  const body = new FormData();
  body.append("file", fileInput.files[0]);
  body.append("extraText", extraText.value || "");

  try {
    const res = await fetch("/api/analyze", { method: "POST", body });
    const payload = await res.json();
    if (!res.ok || !payload.ok) {
      throw new Error(payload.error || "Analyze request failed");
    }

    renderAnalysis(payload);
    setStatus("Analysis complete.");
    showToast("Analysis complete", "\u2705");
  } catch (error) {
    setStatus(error.message || "Analysis failed.", true);
    showToast(error.message || "Analysis failed", "\u274C");
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Run Full Analysis
    `;
  }
});

// ---- Prompt Scan Submit ----
promptForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = promptText.value.trim();

  if (!text) {
    setStatus("Enter text for prompt scan.", true);
    return;
  }

  promptBtn.disabled = true;
  promptBtn.innerHTML = `<span class="spinner"></span> Scanning...`;
  setStatus("Scanning prompt text...");

  try {
    const res = await fetch("/api/prompt-scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const payload = await res.json();
    if (!res.ok || !payload.ok) {
      throw new Error(payload.error || "Prompt scan failed");
    }

    renderPromptOnly(payload);
    setStatus("Prompt scan complete.");
    showToast("Scan complete", "\u2705");
  } catch (error) {
    setStatus(error.message || "Prompt scan failed.", true);
    showToast(error.message || "Scan failed", "\u274C");
  } finally {
    promptBtn.disabled = false;
    promptBtn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      Scan for Injection Patterns
    `;
  }
});

// ---- Scanner Mode ----
async function loadScannerMode() {
  if (!modeBanner) return;
  try {
    const res = await fetch("/health");
    const health = await res.json();
    const isFull = Boolean(health.virustotalConfigured);
    modeBanner.innerHTML = `<span class="dot"></span> ${
      isFull
        ? "Local + VirusTotal"
        : "Local only"
    } &middot; ${health.injectionRules || 30} rules`;
    modeBanner.classList.add(isFull ? "full" : "local-only");
  } catch {
    modeBanner.innerHTML = `<span class="dot"></span> Unavailable`;
  }
}

// Make copyToClipboard globally accessible for onclick handlers
window.copyToClipboard = copyToClipboard;

loadScannerMode();
