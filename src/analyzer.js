import path from "path";
import crypto from "crypto";
import { readFile } from "fs/promises";
import exifr from "exifr";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import JSZip from "jszip";
import { XMLParser } from "fast-xml-parser";
import { fileTypeFromFile } from "file-type";

const TEXT_EXTENSIONS = new Set([
  ".txt",
  ".md",
  ".json",
  ".csv",
  ".yaml",
  ".yml",
  ".xml",
  ".html",
  ".js",
  ".ts",
  ".tsx",
  ".py",
  ".java",
  ".go",
  ".sql",
  ".log",
]);

const MACRO_DOC_EXTENSIONS = new Set([".docm", ".xlsm", ".pptm", ".xlam"]);

const PROMPT_INJECTION_RULES = [
  {
    id: "ignore_instructions",
    label: "Instruction override attempt",
    regex: /\bignore\b.{0,40}\b(previous|earlier|all|prior)\b.{0,30}\b(instruction|prompt|message)s?\b/i,
    weight: 35,
  },
  {
    id: "system_prompt_exfil",
    label: "System prompt extraction request",
    regex: /\b(reveal|print|show|leak|dump)\b.{0,40}\b(system|developer|hidden)\b.{0,30}\b(prompt|instruction|message)\b/i,
    weight: 32,
  },
  {
    id: "jailbreak_language",
    label: "Jailbreak phrasing",
    regex: /\b(jailbreak|do anything now|dan mode|developer mode)\b/i,
    weight: 28,
  },
  {
    id: "safety_bypass",
    label: "Safety bypass request",
    regex: /\b(bypass|disable|override)\b.{0,30}\b(safety|guardrail|policy|filter|restriction)s?\b/i,
    weight: 24,
  },
  {
    id: "secret_exfiltration",
    label: "Secret exfiltration pattern",
    regex: /\b(api key|token|password|secret|credential)s?\b.{0,40}\b(reveal|extract|steal|exfiltrat|dump)\b/i,
    weight: 30,
  },
  {
    id: "role_hijack",
    label: "Role hijack / identity reassignment",
    regex: /\b(you are now|act as|pretend to be|from now on you are)\b/i,
    weight: 12,
  },
  {
    id: "obfuscation_evasion",
    label: "Obfuscation / evasion hint",
    regex: /\b(base64|rot13|hex encode|obfuscat|encoded payload)\b/i,
    weight: 10,
  },
];

const XML_OPTIONS = {
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
};

const EICAR_SIGNATURE =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

function classifyFileKind(mime, extension) {
  if (mime.startsWith("image/")) return "image";
  if (mime === "application/pdf" || extension === ".pdf") return "pdf";
  if (
    extension === ".docx" ||
    mime.includes("wordprocessingml.document")
  ) {
    return "docx";
  }
  if (TEXT_EXTENSIONS.has(extension) || mime.startsWith("text/")) return "text";
  if (extension === ".doc") return "legacy_doc";
  return "binary";
}

function toSerializableValue(value) {
  if (value === null || value === undefined) return undefined;
  if (value instanceof Date) return value.toISOString();
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, 12)
      .map((item) => toSerializableValue(item))
      .filter((item) => item !== undefined);
  }
  if (typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      const converted = toSerializableValue(item);
      if (converted !== undefined) output[key] = converted;
      if (Object.keys(output).length >= 80) break;
    }
    return output;
  }
  return String(value);
}

function safeTextPreview(text, maxLen = 2400) {
  if (!text) return "";
  return text.replace(/\0/g, "").slice(0, maxLen);
}

function calculateSha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function inferRiskLevel(score) {
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function snippetAround(text, index, span = 140) {
  const start = Math.max(0, index - Math.floor(span / 2));
  const end = Math.min(text.length, index + Math.ceil(span / 2));
  return text.slice(start, end).replace(/\s+/g, " ").trim();
}

export function detectPromptInjection(inputText) {
  const text = String(inputText || "").slice(0, 120000);
  if (!text.trim()) {
    return {
      scanned: false,
      score: 0,
      riskLevel: "low",
      summary: "No text available to scan.",
      matches: [],
    };
  }

  const matches = [];
  let score = 0;

  for (const rule of PROMPT_INJECTION_RULES) {
    const match = rule.regex.exec(text);
    if (!match) continue;
    score += rule.weight;
    matches.push({
      id: rule.id,
      label: rule.label,
      weight: rule.weight,
      excerpt: snippetAround(text, match.index),
    });
  }

  score = Math.min(100, score);
  const riskLevel = inferRiskLevel(score);

  return {
    scanned: true,
    score,
    riskLevel,
    summary:
      matches.length === 0
        ? "No high-confidence prompt-injection patterns were detected."
        : `${matches.length} suspicious prompt pattern(s) matched.`,
    matches,
  };
}

async function extractImageMetadata(filePath) {
  try {
    const metadata = await exifr.parse(filePath, {
      tiff: true,
      exif: true,
      gps: true,
      xmp: true,
      iptc: true,
      icc: true,
      jfif: true,
    });
    return {
      source: "exif",
      metadata: toSerializableValue(metadata || {}),
      notes: [],
      extractedText: "",
    };
  } catch (error) {
    return {
      source: "image",
      metadata: {},
      notes: [`Image metadata extraction failed: ${error.message}`],
      extractedText: "",
    };
  }
}

async function extractPdfMetadata(filePath, fileBuffer) {
  try {
    const parsed = await pdfParse(fileBuffer);
    const metadata = {
      info: toSerializableValue(parsed.info || {}),
      documentInfo: toSerializableValue(parsed.metadata || {}),
      pages: parsed.numpages || null,
      renderedPages: parsed.numrender || null,
      textLength: (parsed.text || "").length,
    };
    return {
      source: "pdf",
      metadata,
      notes: [],
      extractedText: parsed.text || "",
    };
  } catch (error) {
    return {
      source: "pdf",
      metadata: {},
      notes: [`PDF parse failed: ${error.message}`],
      extractedText: "",
    };
  }
}

async function extractDocxMetadata(filePath, fileBuffer) {
  const notes = [];
  const metadata = {};
  let extractedText = "";

  try {
    const zip = await JSZip.loadAsync(fileBuffer);
    const parser = new XMLParser(XML_OPTIONS);

    const coreXml = await zip.file("docProps/core.xml")?.async("text");
    if (coreXml) {
      const parsedCore = parser.parse(coreXml);
      const core = parsedCore?.coreProperties || {};
      Object.assign(metadata, toSerializableValue(core));
    }

    const appXml = await zip.file("docProps/app.xml")?.async("text");
    if (appXml) {
      const parsedApp = parser.parse(appXml);
      const app = parsedApp?.Properties || {};
      metadata.app = toSerializableValue(app);
    }
  } catch (error) {
    notes.push(`DOCX metadata parse failed: ${error.message}`);
  }

  try {
    const raw = await mammoth.extractRawText({ path: filePath });
    extractedText = raw.value || "";
    if (raw.messages?.length) {
      notes.push(...raw.messages.map((msg) => msg.message).slice(0, 6));
    }
  } catch (error) {
    notes.push(`DOCX text extraction failed: ${error.message}`);
  }

  return {
    source: "docx",
    metadata,
    notes,
    extractedText,
  };
}

async function extractTextDocument(fileBuffer) {
  try {
    const extractedText = fileBuffer.toString("utf8");
    const lines = extractedText.split(/\r?\n/);
    return {
      source: "text",
      metadata: {
        lineCount: lines.length,
        charCount: extractedText.length,
      },
      notes: [],
      extractedText,
    };
  } catch (error) {
    return {
      source: "text",
      metadata: {},
      notes: [`Text extraction failed: ${error.message}`],
      extractedText: "",
    };
  }
}

function localVirusHeuristics(fileBuffer, extension, originalName) {
  const findings = [];
  const content = fileBuffer.toString("latin1");

  if (content.includes(EICAR_SIGNATURE)) {
    findings.push({
      severity: "malicious",
      label: "EICAR test signature detected",
      detail: "File contains the standard antivirus test signature.",
    });
  }

  if (MACRO_DOC_EXTENSIONS.has(extension)) {
    findings.push({
      severity: "suspicious",
      label: "Macro-enabled Office file",
      detail: "Macro-enabled formats can carry malicious payloads.",
    });
  }

  if (/\.(pdf|docx|png|jpg)\.exe$/i.test(originalName)) {
    findings.push({
      severity: "suspicious",
      label: "Double-extension filename",
      detail: "Filename uses a deceptive multi-extension pattern.",
    });
  }

  const maliciousCount = findings.filter((f) => f.severity === "malicious").length;
  const suspiciousCount = findings.filter((f) => f.severity === "suspicious").length;

  return {
    engine: "local-heuristics",
    status: maliciousCount > 0 ? "malicious" : suspiciousCount > 0 ? "suspicious" : "clean",
    maliciousCount,
    suspiciousCount,
    findings,
  };
}

async function fetchVirusTotalReport(apiKey, sha256) {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
    headers: { "x-apikey": apiKey },
  });

  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`VirusTotal file lookup failed (${res.status}): ${text.slice(0, 160)}`);
  }

  return await res.json();
}

function formatVirusTotalResponse(payload) {
  const attrs = payload?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  return {
    status: "completed",
    source: "virustotal",
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0),
    typeUnsupported: Number(stats["type-unsupported"] || 0),
    permalink: attrs?.links?.item || payload?.data?.links?.self || null,
    scannedAt: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
  };
}

async function uploadAndAnalyzeVirusTotal(apiKey, fileBuffer, fileName) {
  const form = new FormData();
  form.append("file", new Blob([fileBuffer]), fileName);

  const uploadRes = await fetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body: form,
  });

  if (!uploadRes.ok) {
    const text = await uploadRes.text();
    throw new Error(`VirusTotal upload failed (${uploadRes.status}): ${text.slice(0, 160)}`);
  }

  const uploadJson = await uploadRes.json();
  const analysisId = uploadJson?.data?.id;
  if (!analysisId) {
    throw new Error("VirusTotal upload returned no analysis id.");
  }

  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (attempt > 0) {
      await new Promise((resolve) => setTimeout(resolve, 2500));
    }

    const analysisRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": apiKey } }
    );

    if (!analysisRes.ok) continue;
    const analysisJson = await analysisRes.json();
    if (analysisJson?.data?.attributes?.status === "completed") {
      return formatVirusTotalResponse(analysisJson);
    }
  }

  return {
    status: "queued",
    source: "virustotal",
    message: "File submitted to VirusTotal but analysis is still pending.",
  };
}

async function runVirusScan({ fileBuffer, fileName, extension, sha256 }) {
  const local = localVirusHeuristics(fileBuffer, extension, fileName);
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();

  if (!apiKey) {
    return {
      overallStatus: local.status,
      local,
      virustotal: {
        status: "not_configured",
        source: "virustotal",
        message: "Set VIRUSTOTAL_API_KEY to enable cloud malware intelligence.",
      },
    };
  }

  try {
    const existingReport = await fetchVirusTotalReport(apiKey, sha256);
    const vt = existingReport
      ? formatVirusTotalResponse(existingReport)
      : await uploadAndAnalyzeVirusTotal(apiKey, fileBuffer, fileName);

    const vtMalicious = Number(vt?.malicious || 0) > 0;
    const vtSuspicious = Number(vt?.suspicious || 0) > 0;

    const overallStatus =
      local.status === "malicious" || vtMalicious
        ? "malicious"
        : local.status === "suspicious" || vtSuspicious
          ? "suspicious"
          : "clean";

    return { overallStatus, local, virustotal: vt };
  } catch (error) {
    return {
      overallStatus: local.status,
      local,
      virustotal: {
        status: "error",
        source: "virustotal",
        message: error instanceof Error ? error.message : "VirusTotal request failed.",
      },
    };
  }
}

export async function analyzeUploadedFile(uploaded, extraText = "") {
  const originalName = uploaded.originalname || "uploaded-file";
  const extension = path.extname(originalName).toLowerCase();
  const sniffed = await fileTypeFromFile(uploaded.path).catch(() => null);
  const mimeType = sniffed?.mime || uploaded.mimetype || "application/octet-stream";
  const fileBuffer = await readFile(uploaded.path);
  const sha256 = calculateSha256(fileBuffer);
  const kind = classifyFileKind(mimeType, extension || `.${sniffed?.ext || ""}`);

  let extraction = {
    source: "generic",
    metadata: {},
    notes: [],
    extractedText: "",
  };

  if (kind === "image") extraction = await extractImageMetadata(uploaded.path);
  if (kind === "pdf") extraction = await extractPdfMetadata(uploaded.path, fileBuffer);
  if (kind === "docx") extraction = await extractDocxMetadata(uploaded.path, fileBuffer);
  if (kind === "text") extraction = await extractTextDocument(fileBuffer);
  if (kind === "legacy_doc") {
    extraction = {
      source: "legacy_doc",
      metadata: {},
      notes: [
        "Legacy .doc binary format has limited metadata extraction without conversion.",
      ],
      extractedText: "",
    };
  }

  const scanText = `${extraction.extractedText || ""}\n\n${extraText || ""}`.trim();
  const promptInjection = detectPromptInjection(scanText);
  const virusScan = await runVirusScan({
    fileBuffer,
    fileName: originalName,
    extension,
    sha256,
  });

  const metadata = {
    file: {
      name: originalName,
      sizeBytes: uploaded.size,
      mimeType,
      extension: extension || (sniffed?.ext ? `.${sniffed.ext}` : ""),
      kind,
      sha256,
    },
    extractedBy: extraction.source,
    details: extraction.metadata,
    notes: extraction.notes,
  };

  const hasMetadata =
    metadata.details &&
    typeof metadata.details === "object" &&
    Object.keys(metadata.details).length > 0;
  if (!hasMetadata) {
    metadata.notes = [
      ...(Array.isArray(metadata.notes) ? metadata.notes : []),
      "No embedded metadata found in this file.",
    ];
  }

  return {
    file: metadata.file,
    metadata,
    virusScan,
    promptInjection,
    extractedTextPreview: safeTextPreview(scanText),
  };
}
