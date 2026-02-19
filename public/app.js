const analyzeForm = document.getElementById("analyze-form");
const promptForm = document.getElementById("prompt-form");
const fileInput = document.getElementById("file-input");
const extraText = document.getElementById("extra-text");
const promptText = document.getElementById("prompt-text");
const analyzeBtn = document.getElementById("analyze-btn");
const promptBtn = document.getElementById("prompt-btn");
const results = document.getElementById("results");
const statusLine = document.getElementById("status");
const modeBanner = document.getElementById("mode-banner");

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.className = `status ${isError ? "" : "muted"}`;
  if (isError) statusLine.style.color = "#ff7a7a";
  else statusLine.style.color = "";
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function jsonBlock(data) {
  return `<pre class="code-block">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
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

function renderAnalysis(payload) {
  const file = payload.file || {};
  const metadata = payload.metadata || {};
  const virusScan = payload.virusScan || {};
  const promptInjection = payload.promptInjection || {};

  const cards = [];

  cards.push(`
    <article class="card">
      <h3>File Summary</h3>
      <ul class="kv-list">
        <li><strong>Name:</strong> ${escapeHtml(file.name || "Unknown")}</li>
        <li><strong>Type:</strong> ${escapeHtml(file.kind || "unknown")} (${escapeHtml(file.mimeType || "unknown")})</li>
        <li><strong>Size:</strong> ${formatBytes(file.sizeBytes)}</li>
        <li><strong>SHA256:</strong> ${escapeHtml(file.sha256 || "n/a")}</li>
      </ul>
    </article>
  `);

  cards.push(`
    <article class="card">
      <h3>Prompt Injection</h3>
      <p>${badge(promptInjection.riskLevel)}</p>
      <ul class="kv-list">
        <li><strong>Score:</strong> ${Number(promptInjection.score || 0)}/100</li>
        <li><strong>Summary:</strong> ${escapeHtml(promptInjection.summary || "No result")}</li>
        <li><strong>Matches:</strong> ${Array.isArray(promptInjection.matches) ? promptInjection.matches.length : 0}</li>
      </ul>
      ${
        Array.isArray(promptInjection.matches) && promptInjection.matches.length
          ? jsonBlock(promptInjection.matches)
          : ""
      }
    </article>
  `);

  cards.push(`
    <article class="card">
      <h3>Virus Scan</h3>
      <p>${badge(virusScan.overallStatus === "malicious" ? "high" : virusScan.overallStatus === "suspicious" ? "medium" : "low")}</p>
      <ul class="kv-list">
        <li><strong>Overall:</strong> ${escapeHtml(virusScan.overallStatus || "unknown")}</li>
        <li><strong>Local Engine:</strong> ${escapeHtml(virusScan.local?.status || "n/a")}</li>
        <li><strong>VirusTotal:</strong> ${escapeHtml(virusScan.virustotal?.status || "n/a")}</li>
      </ul>
      ${jsonBlock(virusScan)}
    </article>
  `);

  cards.push(`
    <article class="card">
      <h3>Metadata</h3>
      ${jsonBlock(metadata)}
    </article>
  `);

  cards.push(`
    <article class="card">
      <h3>Extracted Text Preview</h3>
      ${jsonBlock(payload.extractedTextPreview || "")}
    </article>
  `);

  results.innerHTML = cards.join("\n");
}

function renderPromptOnly(payload) {
  const promptInjection = payload.promptInjection || {};
  results.innerHTML = `
    <article class="card">
      <h3>Prompt Injection Result</h3>
      <p>${badge(promptInjection.riskLevel)}</p>
      ${jsonBlock(promptInjection)}
    </article>
  `;
}

analyzeForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!fileInput.files?.length) {
    setStatus("Choose a file first.", true);
    return;
  }

  analyzeBtn.disabled = true;
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
  } catch (error) {
    setStatus(error.message || "Analysis failed.", true);
  } finally {
    analyzeBtn.disabled = false;
  }
});

promptForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = promptText.value.trim();

  if (!text) {
    setStatus("Enter text for prompt scan.", true);
    return;
  }

  promptBtn.disabled = true;
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
  } catch (error) {
    setStatus(error.message || "Prompt scan failed.", true);
  } finally {
    promptBtn.disabled = false;
  }
});

async function loadScannerMode() {
  if (!modeBanner) return;
  try {
    const res = await fetch("/health");
    const health = await res.json();
    const isFull = Boolean(health.virustotalConfigured);
    modeBanner.textContent = isFull
      ? "Scanner Mode: Local + VirusTotal"
      : "Scanner Mode: Local only (set VIRUSTOTAL_API_KEY for cloud malware intel)";
    modeBanner.classList.add(isFull ? "full" : "local-only");
  } catch {
    modeBanner.textContent = "Scanner mode unavailable";
  }
}

loadScannerMode();
