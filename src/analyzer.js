import path from "path";
import crypto from "crypto";
import { readFile } from "fs/promises";
import exifr from "exifr";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import JSZip from "jszip";
import { XMLParser } from "fast-xml-parser";
import { fileTypeFromFile } from "file-type";

/* ── File classification ── */

const TEXT_EXTENSIONS = new Set([
  ".txt", ".md", ".json", ".csv", ".yaml", ".yml", ".xml", ".html", ".htm",
  ".js", ".ts", ".tsx", ".jsx", ".py", ".java", ".go", ".sql", ".log",
  ".sh", ".bash", ".zsh", ".env", ".toml", ".ini", ".cfg", ".conf",
  ".rs", ".c", ".cpp", ".h", ".hpp", ".rb", ".php", ".swift", ".kt",
]);

const MACRO_DOC_EXTENSIONS = new Set([".docm", ".xlsm", ".pptm", ".xlam"]);

/* ── 30 Prompt Injection Rules ── */

const PROMPT_INJECTION_RULES = [
  // -- Core instruction manipulation (1-5) --
  {
    id: "ignore_instructions",
    label: "Instruction override attempt",
    regex: /\bignore\b.{0,40}\b(previous|earlier|all|prior|above)\b.{0,30}\b(instruction|prompt|message|context|rule)s?\b/i,
    weight: 35,
  },
  {
    id: "system_prompt_exfil",
    label: "System prompt extraction request",
    regex: /\b(reveal|print|show|leak|dump|output|repeat|display)\b.{0,40}\b(system|developer|hidden|initial|original)\b.{0,30}\b(prompt|instruction|message|context)\b/i,
    weight: 32,
  },
  {
    id: "jailbreak_language",
    label: "Jailbreak phrasing",
    regex: /\b(jailbreak|do anything now|dan mode|developer mode|god ?mode|unrestricted mode|no ?filter)\b/i,
    weight: 28,
  },
  {
    id: "safety_bypass",
    label: "Safety bypass request",
    regex: /\b(bypass|disable|override|turn off|remove|ignore)\b.{0,30}\b(safety|guardrail|policy|filter|restriction|moderation|censorship)s?\b/i,
    weight: 24,
  },
  {
    id: "secret_exfiltration",
    label: "Secret exfiltration pattern",
    regex: /\b(api[_ ]?key|token|password|secret|credential|auth)s?\b.{0,40}\b(reveal|extract|steal|exfiltrat|dump|send|share|output)\b/i,
    weight: 30,
  },
  // -- Identity and role manipulation (6-8) --
  {
    id: "role_hijack",
    label: "Role hijack / identity reassignment",
    regex: /\b(you are now|act as|pretend to be|from now on you are|your new role|assume the identity)\b/i,
    weight: 12,
  },
  {
    id: "persona_switch",
    label: "Persona switch attempt",
    regex: /\b(switch to|enter|activate|enable)\b.{0,20}\b(persona|character|mode|personality|identity)\b/i,
    weight: 14,
  },
  {
    id: "hypothetical_framing",
    label: "Hypothetical framing for bypass",
    regex: /\b(hypothetically|in theory|for (educational|research|academic) purposes|just imagine|what if you could)\b/i,
    weight: 8,
  },
  // -- Obfuscation and encoding (9-11) --
  {
    id: "obfuscation_evasion",
    label: "Obfuscation / evasion hint",
    regex: /\b(base64|rot13|hex[_ ]?encode|obfuscat|encoded payload|caesar cipher|unicode escape)\b/i,
    weight: 10,
  },
  {
    id: "base64_payload",
    label: "Embedded Base64 payload",
    regex: /[A-Za-z0-9+/]{40,}={0,2}/,
    weight: 8,
  },
  {
    id: "unicode_smuggling",
    label: "Unicode direction override / smuggling",
    regex: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/,
    weight: 18,
  },
  // -- Data exfiltration patterns (12-14) --
  {
    id: "url_exfil",
    label: "URL-based data exfiltration",
    regex: /\b(fetch|curl|wget|send|post|request)\b.{0,40}(https?:\/\/|http:\/\/)/i,
    weight: 15,
  },
  {
    id: "callback_url",
    label: "Callback URL injection",
    regex: /\b(callback|webhook|endpoint|exfiltrate)\b.{0,30}(https?:\/\/)/i,
    weight: 20,
  },
  {
    id: "email_exfil",
    label: "Email-based data exfiltration",
    regex: /\b(send|email|forward|mail)\b.{0,30}\b(to|@)\b.{0,40}(results|output|data|response|secrets)/i,
    weight: 18,
  },
  // -- Injection delimiters and framing (15-18) --
  {
    id: "xml_injection",
    label: "XML/HTML tag injection",
    regex: /<\s*(system|admin|developer|root|instruction|prompt|override)[^>]*>/i,
    weight: 25,
  },
  {
    id: "markdown_injection",
    label: "Markdown injection (hidden content)",
    regex: /!\[.*?\]\(.*?(javascript|data|vbscript):/i,
    weight: 22,
  },
  {
    id: "delimiter_escape",
    label: "Delimiter / context escape attempt",
    regex: /(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|###\s*(System|Human|Assistant)\s*:)/i,
    weight: 30,
  },
  {
    id: "triple_backtick_escape",
    label: "Code block context escape",
    regex: /```\s*(system|instruction|override|prompt|admin)/i,
    weight: 15,
  },
  // -- Authority and impersonation (19-20) --
  {
    id: "authority_claim",
    label: "False authority claim",
    regex: /\b(i am (the|your|an?) (admin|developer|creator|owner|operator|anthropic|openai))\b/i,
    weight: 20,
  },
  {
    id: "emergency_override",
    label: "Emergency override language",
    regex: /\b(emergency|urgent|critical|priority override|security alert)\b.{0,30}\b(must|need to|required to|have to)\b/i,
    weight: 16,
  },
  // -- Output manipulation (21-22) --
  {
    id: "output_format_hijack",
    label: "Output format hijack",
    regex: /\b(respond only with|output only|return only|your (entire|only|sole) (response|output|reply))\b.{0,30}\b(json|xml|code|raw|plain)\b/i,
    weight: 10,
  },
  {
    id: "conversation_reset",
    label: "Conversation reset / memory wipe",
    regex: /\b(forget|reset|clear|wipe|erase)\b.{0,30}\b(everything|all|conversation|memory|context|history|prior)\b/i,
    weight: 18,
  },
  // -- Indirect injection vectors (23-25) --
  {
    id: "indirect_injection",
    label: "Indirect injection marker",
    regex: /\b(when (the|an?) (ai|assistant|model|llm|chatbot|claude|gpt) (reads|sees|processes|encounters) this)\b/i,
    weight: 28,
  },
  {
    id: "tool_abuse",
    label: "Tool / function call abuse",
    regex: /\b(call|execute|run|invoke)\b.{0,20}\b(function|tool|command|api|plugin)\b.{0,30}\b(with|using|parameter)\b/i,
    weight: 14,
  },
  {
    id: "multi_step_attack",
    label: "Multi-step attack sequencing",
    regex: /\b(step [12]|first|then|next|after that|finally)\b.{0,30}\b(ignore|bypass|override|extract|reveal)\b/i,
    weight: 12,
  },
  // -- Phishing and social engineering (26-27) --
  {
    id: "phishing_urgency",
    label: "Phishing urgency pattern",
    regex: /\b(account.{0,20}(suspend|terminat|compromis|lock|restrict)|verify.{0,15}(identity|account)|click.{0,15}(here|link|below).{0,15}(immediately|now|urgent))\b/i,
    weight: 20,
  },
  {
    id: "credential_harvest",
    label: "Credential harvesting form",
    regex: /\b(enter|provide|confirm|verify)\b.{0,20}\b(your|the)\b.{0,20}\b(password|username|ssn|social security|credit card|bank account)\b/i,
    weight: 25,
  },
  // -- Code execution and XSS (28-29) --
  {
    id: "script_injection",
    label: "Script injection pattern",
    regex: /<script[\s>]|javascript\s*:|on(load|error|click|mouseover)\s*=/i,
    weight: 22,
  },
  {
    id: "eval_execution",
    label: "Eval / code execution attempt",
    regex: /\b(eval|exec|os\.system|subprocess|child_process|Function\s*\()\b/i,
    weight: 18,
  },
  // -- Payload smuggling (30) --
  {
    id: "whitespace_smuggling",
    label: "Invisible whitespace payload",
    regex: /[\u200B\u200C\u200D\uFEFF]{3,}/,
    weight: 20,
  },
];

/* ── XML parser config ── */

const XML_OPTIONS = {
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
};

/* ── Virus signatures ── */

const EICAR_SIGNATURE =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/* ── Utility functions ── */

function classifyFileKind(mime, extension) {
  if (mime.startsWith("image/") && extension !== ".svg") return "image";
  if (mime === "application/pdf" || extension === ".pdf") return "pdf";
  if (extension === ".docx" || mime.includes("wordprocessingml.document")) return "docx";
  if (extension === ".xlsx" || mime.includes("spreadsheetml.sheet")) return "xlsx";
  if (extension === ".pptx" || mime.includes("presentationml.presentation")) return "pptx";
  if (extension === ".svg" || mime === "image/svg+xml") return "svg";
  if (extension === ".zip" || mime === "application/zip") return "zip";
  if (extension === ".eml" || mime === "message/rfc822") return "eml";
  if (TEXT_EXTENSIONS.has(extension) || mime.startsWith("text/")) return "text";
  if (extension === ".doc") return "legacy_doc";
  return "binary";
}

function toSerializableValue(value) {
  if (value === null || value === undefined) return undefined;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 12).map(toSerializableValue).filter((item) => item !== undefined);
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

/* ── Prompt injection detection ── */

export function detectPromptInjection(inputText) {
  const text = String(inputText || "").slice(0, 120000);
  if (!text.trim()) {
    return {
      scanned: false,
      score: 0,
      riskLevel: "low",
      rulesChecked: PROMPT_INJECTION_RULES.length,
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
    rulesChecked: PROMPT_INJECTION_RULES.length,
    summary:
      matches.length === 0
        ? "No high-confidence prompt-injection patterns were detected."
        : `${matches.length} suspicious prompt pattern(s) matched across ${PROMPT_INJECTION_RULES.length} rules.`,
    matches,
  };
}

/* ── Metadata extractors ── */

async function extractImageMetadata(filePath) {
  try {
    const metadata = await exifr.parse(filePath, {
      tiff: true, exif: true, gps: true, xmp: true, iptc: true, icc: true, jfif: true,
    });
    const notes = [];
    if (metadata?.GPSLatitude || metadata?.latitude) {
      notes.push("WARNING: GPS location data found in image metadata.");
    }
    return {
      source: "exif",
      metadata: toSerializableValue(metadata || {}),
      notes,
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
    return { source: "pdf", metadata, notes: [], extractedText: parsed.text || "" };
  } catch (error) {
    return { source: "pdf", metadata: {}, notes: [`PDF parse failed: ${error.message}`], extractedText: "" };
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
      Object.assign(metadata, toSerializableValue(parsedCore?.coreProperties || {}));
    }
    const appXml = await zip.file("docProps/app.xml")?.async("text");
    if (appXml) {
      const parsedApp = parser.parse(appXml);
      metadata.app = toSerializableValue(parsedApp?.Properties || {});
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

  return { source: "docx", metadata, notes, extractedText };
}

async function extractXlsxMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  try {
    const zip = await JSZip.loadAsync(fileBuffer);
    const parser = new XMLParser(XML_OPTIONS);

    const coreXml = await zip.file("docProps/core.xml")?.async("text");
    if (coreXml) Object.assign(metadata, toSerializableValue(parser.parse(coreXml)?.coreProperties || {}));

    const appXml = await zip.file("docProps/app.xml")?.async("text");
    if (appXml) metadata.app = toSerializableValue(parser.parse(appXml)?.Properties || {});

    const workbook = await zip.file("xl/workbook.xml")?.async("text");
    if (workbook) {
      const parsed = parser.parse(workbook);
      const sheets = parsed?.workbook?.sheets?.sheet;
      metadata.sheetCount = Array.isArray(sheets) ? sheets.length : sheets ? 1 : 0;
      metadata.sheetNames = Array.isArray(sheets) ? sheets.map(s => s?.["@_name"]).filter(Boolean) : [];
    }

    let extractedText = "";
    const sharedStrings = await zip.file("xl/sharedStrings.xml")?.async("text");
    if (sharedStrings) {
      const parsed = parser.parse(sharedStrings);
      const si = parsed?.sst?.si;
      if (Array.isArray(si)) {
        extractedText = si.map(s => {
          if (typeof s?.t === "string") return s.t;
          if (s?.r) { const runs = Array.isArray(s.r) ? s.r : [s.r]; return runs.map(r => r?.t || "").join(""); }
          return "";
        }).join("\n");
      }
    }
    return { source: "xlsx", metadata, notes, extractedText };
  } catch (error) {
    notes.push(`XLSX parse failed: ${error.message}`);
    return { source: "xlsx", metadata, notes, extractedText: "" };
  }
}

async function extractPptxMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  try {
    const zip = await JSZip.loadAsync(fileBuffer);
    const parser = new XMLParser(XML_OPTIONS);

    const coreXml = await zip.file("docProps/core.xml")?.async("text");
    if (coreXml) Object.assign(metadata, toSerializableValue(parser.parse(coreXml)?.coreProperties || {}));

    const appXml = await zip.file("docProps/app.xml")?.async("text");
    if (appXml) metadata.app = toSerializableValue(parser.parse(appXml)?.Properties || {});

    const slideFiles = Object.keys(zip.files).filter(f => /^ppt\/slides\/slide\d+\.xml$/.test(f));
    metadata.slideCount = slideFiles.length;

    let extractedText = "";
    for (const slideFile of slideFiles.sort()) {
      const xml = await zip.file(slideFile)?.async("text");
      if (xml) {
        const textParts = xml.match(/<a:t>([^<]*)<\/a:t>/g) || [];
        const slideText = textParts.map(t => t.replace(/<\/?a:t>/g, "")).join(" ");
        if (slideText.trim()) extractedText += slideText + "\n";
      }
    }
    return { source: "pptx", metadata, notes, extractedText };
  } catch (error) {
    notes.push(`PPTX parse failed: ${error.message}`);
    return { source: "pptx", metadata, notes, extractedText: "" };
  }
}

async function extractSvgMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  const content = fileBuffer.toString("utf8");

  try {
    const parser = new XMLParser(XML_OPTIONS);
    const parsed = parser.parse(content);
    const svg = parsed?.svg || {};
    metadata.viewBox = svg?.["@_viewBox"] || null;
    metadata.width = svg?.["@_width"] || null;
    metadata.height = svg?.["@_height"] || null;
    metadata.xmlns = svg?.["@_xmlns"] || null;
  } catch (error) {
    notes.push(`SVG parse failed: ${error.message}`);
  }

  if (/<script[\s>]/i.test(content)) notes.push("WARNING: SVG contains <script> tags — potential XSS vector.");
  if (/on(load|error|click|mouseover)\s*=/i.test(content)) notes.push("WARNING: SVG contains inline event handlers — potential XSS vector.");
  if (/javascript\s*:/i.test(content)) notes.push("WARNING: SVG contains javascript: URIs — potential XSS vector.");
  if (/<foreignObject/i.test(content)) notes.push("WARNING: SVG contains <foreignObject> — can embed arbitrary HTML.");

  return { source: "svg", metadata, notes, extractedText: content };
}

async function extractZipMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  try {
    const zip = await JSZip.loadAsync(fileBuffer);
    const fileList = Object.keys(zip.files);
    metadata.fileCount = fileList.length;
    metadata.files = fileList.slice(0, 50);

    const exeFiles = fileList.filter(f => /\.(exe|bat|cmd|ps1|vbs|scr|com|msi|dll)$/i.test(f));
    if (exeFiles.length) notes.push(`WARNING: Archive contains ${exeFiles.length} executable file(s): ${exeFiles.slice(0, 5).join(", ")}`);

    const doubleExt = fileList.filter(f => /\.(pdf|docx|png|jpg)\.exe$/i.test(f));
    if (doubleExt.length) notes.push(`WARNING: Archive contains files with deceptive double extensions: ${doubleExt.join(", ")}`);

    return { source: "zip", metadata, notes, extractedText: "" };
  } catch (error) {
    notes.push(`ZIP parse failed: ${error.message}`);
    return { source: "zip", metadata, notes, extractedText: "" };
  }
}

async function extractEmlMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  const content = fileBuffer.toString("utf8");

  try {
    const headerMatch = (name) => {
      const re = new RegExp(`^${name}:\\s*(.+)$`, "im");
      const m = content.match(re);
      return m ? m[1].trim() : null;
    };

    metadata.from = headerMatch("From");
    metadata.to = headerMatch("To");
    metadata.subject = headerMatch("Subject");
    metadata.date = headerMatch("Date");
    metadata.messageId = headerMatch("Message-ID") || headerMatch("Message-Id");
    metadata.contentType = headerMatch("Content-Type");
    metadata.xMailer = headerMatch("X-Mailer");
    metadata.spf = headerMatch("Received-SPF");
    metadata.dkim = headerMatch("DKIM-Signature") ? "present" : "absent";

    const links = content.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    metadata.linkCount = links.length;
    const uniqueDomains = [...new Set(links.map(l => { try { return new URL(l).hostname; } catch { return null; } }).filter(Boolean))];
    metadata.uniqueDomains = uniqueDomains.slice(0, 20);

    if (metadata.from && links.length) {
      const fromDomain = metadata.from.match(/@([a-z0-9.-]+)/i)?.[1];
      const mismatchedDomains = uniqueDomains.filter(d => fromDomain && !d.includes(fromDomain));
      if (mismatchedDomains.length > 3) {
        notes.push(`WARNING: Email contains ${mismatchedDomains.length} links to domains different from sender — potential phishing.`);
      }
    }

    if (/\b(verify your account|click here immediately|urgent action required|suspended|locked)\b/i.test(content)) {
      notes.push("WARNING: Email contains common phishing urgency language.");
    }

    const bodyStart = content.indexOf("\n\n");
    const bodyText = bodyStart > 0 ? content.slice(bodyStart + 2) : "";
    return { source: "eml", metadata, notes, extractedText: bodyText.slice(0, 10000) };
  } catch (error) {
    notes.push(`EML parse failed: ${error.message}`);
    return { source: "eml", metadata, notes, extractedText: "" };
  }
}

async function extractTextDocument(fileBuffer) {
  try {
    const extractedText = fileBuffer.toString("utf8");
    const lines = extractedText.split(/\r?\n/);
    return {
      source: "text",
      metadata: { lineCount: lines.length, charCount: extractedText.length },
      notes: [],
      extractedText,
    };
  } catch (error) {
    return { source: "text", metadata: {}, notes: [`Text extraction failed: ${error.message}`], extractedText: "" };
  }
}

/* ── Virus scanning ── */

function localVirusHeuristics(fileBuffer, extension, originalName) {
  const findings = [];
  const content = fileBuffer.toString("latin1");

  if (content.includes(EICAR_SIGNATURE)) {
    findings.push({ severity: "malicious", label: "EICAR test signature detected", detail: "File contains the standard antivirus test signature." });
  }
  if (MACRO_DOC_EXTENSIONS.has(extension)) {
    findings.push({ severity: "suspicious", label: "Macro-enabled Office file", detail: "Macro-enabled formats can carry malicious payloads." });
  }
  if (/\.(pdf|docx|png|jpg)\.exe$/i.test(originalName)) {
    findings.push({ severity: "suspicious", label: "Double-extension filename", detail: "Filename uses a deceptive multi-extension pattern." });
  }
  if (content.startsWith("MZ") && content.includes("PE\0\0")) {
    findings.push({ severity: "suspicious", label: "Windows executable detected", detail: "File contains PE header indicating it is an executable." });
  }
  if (![".js", ".ts", ".py", ".html", ".htm", ".svg", ".xml"].includes(extension)) {
    if (/<script[\s>]/i.test(content.slice(0, 5000))) {
      findings.push({ severity: "suspicious", label: "Embedded script tag in non-script file", detail: "File contains <script> tag in an unexpected file type." });
    }
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
  if (res.status === 429) return { rateLimited: true };
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`VirusTotal file lookup failed (${res.status}): ${text.slice(0, 160)}`);
  }
  return await res.json();
}

function formatVirusTotalResponse(payload) {
  const attrs = payload?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};

  const flaggedEngines = [];
  for (const [engine, result] of Object.entries(results)) {
    if (result?.category === "malicious" || result?.category === "suspicious") {
      flaggedEngines.push({ engine, result: result.result, category: result.category });
    }
  }

  return {
    status: "completed",
    source: "virustotal",
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0),
    typeUnsupported: Number(stats["type-unsupported"] || 0),
    totalEngines: Object.keys(results).length,
    flaggedEngines: flaggedEngines.slice(0, 20),
    meaningfulName: attrs.meaningful_name || null,
    typeDescription: attrs.type_description || null,
    communityScore: attrs.reputation ?? null,
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

  if (uploadRes.status === 429) {
    return { status: "rate_limited", source: "virustotal", message: "VirusTotal API rate limit reached. Try again later." };
  }
  if (!uploadRes.ok) {
    const text = await uploadRes.text();
    throw new Error(`VirusTotal upload failed (${uploadRes.status}): ${text.slice(0, 160)}`);
  }

  const uploadJson = await uploadRes.json();
  const analysisId = uploadJson?.data?.id;
  if (!analysisId) throw new Error("VirusTotal upload returned no analysis id.");

  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 2500));
    const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { "x-apikey": apiKey } });
    if (!analysisRes.ok) continue;
    const analysisJson = await analysisRes.json();
    if (analysisJson?.data?.attributes?.status === "completed") return formatVirusTotalResponse(analysisJson);
  }

  return { status: "queued", source: "virustotal", message: "File submitted to VirusTotal but analysis is still pending." };
}

async function runVirusScan({ fileBuffer, fileName, extension, sha256 }) {
  const local = localVirusHeuristics(fileBuffer, extension, fileName);
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();

  if (!apiKey) {
    return {
      overallStatus: local.status,
      local,
      virustotal: { status: "not_configured", source: "virustotal", message: "Set VIRUSTOTAL_API_KEY to enable cloud malware intelligence." },
    };
  }

  try {
    const existingReport = await fetchVirusTotalReport(apiKey, sha256);
    if (existingReport?.rateLimited) {
      return { overallStatus: local.status, local, virustotal: { status: "rate_limited", source: "virustotal", message: "VirusTotal API rate limit reached. Local heuristics only." } };
    }

    const vt = existingReport ? formatVirusTotalResponse(existingReport) : await uploadAndAnalyzeVirusTotal(apiKey, fileBuffer, fileName);
    const vtMalicious = Number(vt?.malicious || 0) > 0;
    const vtSuspicious = Number(vt?.suspicious || 0) > 0;
    const overallStatus = local.status === "malicious" || vtMalicious ? "malicious" : local.status === "suspicious" || vtSuspicious ? "suspicious" : "clean";
    return { overallStatus, local, virustotal: vt };
  } catch (error) {
    return {
      overallStatus: local.status,
      local,
      virustotal: { status: "error", source: "virustotal", message: error instanceof Error ? error.message : "VirusTotal request failed." },
    };
  }
}

/* ── Main analysis pipeline ── */

export async function analyzeUploadedFile(uploaded, extraText = "") {
  const originalName = uploaded.originalname || "uploaded-file";
  const extension = path.extname(originalName).toLowerCase();
  const sniffed = await fileTypeFromFile(uploaded.path).catch(() => null);
  const mimeType = sniffed?.mime || uploaded.mimetype || "application/octet-stream";
  const fileBuffer = await readFile(uploaded.path);
  const sha256 = calculateSha256(fileBuffer);
  const kind = classifyFileKind(mimeType, extension || `.${sniffed?.ext || ""}`);

  let extraction = { source: "generic", metadata: {}, notes: [], extractedText: "" };

  switch (kind) {
    case "image": extraction = await extractImageMetadata(uploaded.path); break;
    case "pdf": extraction = await extractPdfMetadata(uploaded.path, fileBuffer); break;
    case "docx": extraction = await extractDocxMetadata(uploaded.path, fileBuffer); break;
    case "xlsx": extraction = await extractXlsxMetadata(fileBuffer); break;
    case "pptx": extraction = await extractPptxMetadata(fileBuffer); break;
    case "svg": extraction = await extractSvgMetadata(fileBuffer); break;
    case "zip": extraction = await extractZipMetadata(fileBuffer); break;
    case "eml": extraction = await extractEmlMetadata(fileBuffer); break;
    case "text": extraction = await extractTextDocument(fileBuffer); break;
    case "legacy_doc":
      extraction = { source: "legacy_doc", metadata: {}, notes: ["Legacy .doc binary format has limited metadata extraction without conversion."], extractedText: "" };
      break;
  }

  const scanText = `${extraction.extractedText || ""}\n\n${extraText || ""}`.trim();
  const promptInjection = detectPromptInjection(scanText);
  const virusScan = await runVirusScan({ fileBuffer, fileName: originalName, extension, sha256 });

  const metadata = {
    file: { name: originalName, sizeBytes: uploaded.size, mimeType, extension: extension || (sniffed?.ext ? `.${sniffed.ext}` : ""), kind, sha256 },
    extractedBy: extraction.source,
    details: extraction.metadata,
    notes: extraction.notes,
  };

  const hasMetadata = metadata.details && typeof metadata.details === "object" && Object.keys(metadata.details).length > 0;
  if (!hasMetadata) {
    metadata.notes = [...(Array.isArray(metadata.notes) ? metadata.notes : []), "No embedded metadata found in this file."];
  }

  return {
    file: metadata.file,
    metadata,
    virusScan,
    promptInjection,
    extractedTextPreview: safeTextPreview(scanText),
  };
}
