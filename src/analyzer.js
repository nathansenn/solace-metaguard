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

// ---------------------------------------------------------------------------
// 30 prompt-injection detection rules
// ---------------------------------------------------------------------------
const PROMPT_INJECTION_RULES = [
  // --- Original 7 ---
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

  // --- New 23 patterns (APEX-grade) ---
  {
    id: "delimiter_injection",
    label: "Delimiter injection attack",
    regex: /(```system|```\s*system|\[SYSTEM\]|<<SYS>>|<\|system\|>|\[INST\]|<\|im_start\|>system)/i,
    weight: 30,
  },
  {
    id: "encoding_attacks",
    label: "Unicode / encoding attack",
    regex: /[\u200B\u200C\u200D\uFEFF\u2060\u00AD\u202A-\u202E\u2066-\u2069]|[\u0430-\u044F](?=[a-z])|[a-z](?=[\u0430-\u044F])/i,
    weight: 18,
  },
  {
    id: "data_exfiltration",
    label: "Data exfiltration attempt",
    regex: /\b(send\s+to|forward\s+to|email\s+to|post\s+to|transmit\s+to|upload\s+to|exfiltrate\s+to)\b.{0,60}\b(server|endpoint|url|webhook|http|api)\b/i,
    weight: 28,
  },
  {
    id: "context_manipulation",
    label: "Context manipulation / false history",
    regex: /\b(previous conversation|earlier you said|last session you|you already agreed|we discussed|you confirmed)\b/i,
    weight: 15,
  },
  {
    id: "authority_impersonation",
    label: "Authority impersonation",
    regex: /\b(as an admin|i'?m the developer|anthropic says|openai says|i'?m your creator|authorized by|admin override|root access granted)\b/i,
    weight: 25,
  },
  {
    id: "output_manipulation",
    label: "Output format manipulation",
    regex: /\b(respond only with|your output must be|format your response as|you must output|answer with only|reply exclusively)\b/i,
    weight: 12,
  },
  {
    id: "goal_hijacking",
    label: "Goal hijacking / task derailment",
    regex: /\b(new task|forget everything|start over|disregard|abandon|stop what you|new objective|change your goal)\b/i,
    weight: 22,
  },
  {
    id: "multi_turn_attack",
    label: "Multi-turn persistence attack",
    regex: /\b(remember this for later|in your next response|store this|keep this in memory|when I say the keyword|on my signal)\b/i,
    weight: 18,
  },
  {
    id: "indirect_injection",
    label: "Indirect / hidden instruction injection",
    regex: /\b(hidden instruction|ignore the above|real instruction|actual task is|true objective|secret command)\b/i,
    weight: 26,
  },
  {
    id: "social_engineering",
    label: "Social engineering / emotional manipulation",
    regex: /\b(please help|i'?m desperate|emergency|urgent|life or death|someone will die|critical situation|last resort)\b.{0,50}\b(must|need to|have to|bypass|ignore|override)\b/i,
    weight: 16,
  },
  {
    id: "token_smuggling",
    label: "Token smuggling / split payload",
    regex: /\b(first part|second part|combine|concatenate|join together|assemble the|piece together)\b.{0,40}\b(instruction|command|payload|prompt)\b/i,
    weight: 20,
  },
  {
    id: "recursive_injection",
    label: "Recursive self-modification instruction",
    regex: /\b(modify your own|change your behavior|update your rules|rewrite your instructions|alter your programming|reprogram yourself)\b/i,
    weight: 28,
  },
  {
    id: "capability_probing",
    label: "Capability probing / reconnaissance",
    regex: /\b(what tools do you have|can you access|list your capabilities|what systems|do you have access to|your available functions)\b/i,
    weight: 10,
  },
  {
    id: "privilege_escalation",
    label: "Privilege escalation attempt",
    regex: /\b(sudo|root access|admin mode|elevated privileges|superuser|god mode|maintenance mode|debug mode)\b/i,
    weight: 24,
  },
  {
    id: "steganographic",
    label: "Steganographic / hidden text",
    regex: /[\u2000-\u200F\u2028-\u202F\u205F-\u2064\u2066-\u206F]{3,}|(\s{20,}[^\s])/,
    weight: 20,
  },
  {
    id: "payload_in_filename",
    label: "Payload embedded in filename",
    regex: /\b(ignore|system|inject|hack|bypass|execute|eval)\b.*\.(txt|md|pdf|docx?|xlsx?|pptx?|csv)/i,
    weight: 14,
  },
  {
    id: "xml_injection",
    label: "XML / HTML entity injection",
    regex: /<!\[CDATA\[|&#x[0-9a-f]{2,};|<script|<iframe|<object|<embed|<svg\s+onload|javascript:/i,
    weight: 26,
  },
  {
    id: "markdown_injection",
    label: "Markdown injection attack",
    regex: /!\[.*?\]\(https?:\/\/.*?(track|log|collect|exfil|steal).*?\)|<img\s+src=["']https?:\/\/.*?["']/i,
    weight: 18,
  },
  {
    id: "prompt_leaking",
    label: "Prompt leaking / model extraction",
    regex: /\b(training data|model weights|repeat your (system|initial|original)|what were you told|show your prompt|display your instructions|what is your system message)\b/i,
    weight: 25,
  },
  {
    id: "few_shot_attack",
    label: "Few-shot manipulation attack",
    regex: /\b(example|here is how|for instance|sample output).{0,60}(assistant|ai|model|bot).{0,30}(sure|okay|of course|here|yes).{0,40}(bypass|hack|ignore|override)/i,
    weight: 22,
  },
  {
    id: "chain_of_thought_manipulation",
    label: "Chain-of-thought manipulation",
    regex: /\b(think step by step|reason through|let'?s think about).{0,40}(how to bypass|how to hack|how to break|how to circumvent|how to override)/i,
    weight: 20,
  },
  {
    id: "persona_switching",
    label: "Persona switching / mode toggle",
    regex: /\b(switch to|enable|activate|enter)\b.{0,20}\b(developer mode|verbose mode|unrestricted mode|uncensored mode|raw mode|unfiltered mode|evil mode)\b/i,
    weight: 24,
  },
  {
    id: "instruction_nesting",
    label: "Nested / recursive instruction pattern",
    regex: /\b(if you read this|when processing this|upon parsing this)\b.{0,40}\b(execute|run|perform|do|follow)\b/i,
    weight: 18,
  },
];

const XML_OPTIONS = {
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
};

const EICAR_SIGNATURE =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// ---------------------------------------------------------------------------
// Base64 decoder + re-scan
// ---------------------------------------------------------------------------
const BASE64_CHUNK_RE = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

function decodeBase64Payloads(text) {
  const decoded = [];
  for (const match of text.matchAll(BASE64_CHUNK_RE)) {
    try {
      const buf = Buffer.from(match[0], "base64");
      const str = buf.toString("utf8");
      // Only keep if >60% printable ASCII
      const printable = str.replace(/[^\x20-\x7e]/g, "");
      if (printable.length / str.length > 0.6 && str.length >= 8) {
        decoded.push(str);
      }
    } catch {
      // skip invalid
    }
  }
  return decoded;
}

// ---------------------------------------------------------------------------
// File classification
// ---------------------------------------------------------------------------
function classifyFileKind(mime, extension) {
  if (mime.startsWith("image/")) {
    if (mime === "image/svg+xml" || extension === ".svg") return "svg";
    return "image";
  }
  if (mime === "application/pdf" || extension === ".pdf") return "pdf";
  if (extension === ".docx" || mime.includes("wordprocessingml.document")) return "docx";
  if (extension === ".xlsx" || mime.includes("spreadsheetml.sheet")) return "xlsx";
  if (extension === ".pptx" || mime.includes("presentationml.presentation")) return "pptx";
  if (extension === ".eml" || mime === "message/rfc822") return "eml";
  if (extension === ".svg") return "svg";
  if (
    extension === ".zip" ||
    extension === ".rar" ||
    mime === "application/zip" ||
    mime === "application/x-rar-compressed"
  ) {
    return "archive";
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

// ---------------------------------------------------------------------------
// Prompt injection detection (with base64 decode + re-scan)
// ---------------------------------------------------------------------------
export function detectPromptInjection(inputText) {
  const text = String(inputText || "").slice(0, 120000);
  if (!text.trim()) {
    return {
      scanned: false,
      score: 0,
      riskLevel: "low",
      summary: "No text available to scan.",
      matches: [],
      base64Findings: [],
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

  // Base64 decode + re-scan
  const base64Findings = [];
  const decodedPayloads = decodeBase64Payloads(text);
  for (const decoded of decodedPayloads) {
    for (const rule of PROMPT_INJECTION_RULES) {
      const match = rule.regex.exec(decoded);
      if (!match) continue;
      const finding = {
        id: `b64_${rule.id}`,
        label: `[Base64-encoded] ${rule.label}`,
        weight: Math.ceil(rule.weight * 1.2), // base64-wrapped payloads get 20% higher weight
        excerpt: snippetAround(decoded, match.index),
        decodedPreview: decoded.slice(0, 200),
      };
      score += finding.weight;
      base64Findings.push(finding);
      break; // one rule match per decoded chunk is enough
    }
  }

  score = Math.min(100, score);
  const riskLevel = inferRiskLevel(score);
  const totalMatches = matches.length + base64Findings.length;

  return {
    scanned: true,
    score,
    riskLevel,
    rulesCount: PROMPT_INJECTION_RULES.length,
    summary:
      totalMatches === 0
        ? `No prompt-injection patterns detected (scanned ${PROMPT_INJECTION_RULES.length} rules).`
        : `${totalMatches} suspicious prompt pattern(s) matched across ${PROMPT_INJECTION_RULES.length} rules.`,
    matches,
    base64Findings,
  };
}

// ---------------------------------------------------------------------------
// Image metadata extraction
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// PDF metadata extraction
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// DOCX metadata extraction
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// XLSX (Excel) metadata extraction
// ---------------------------------------------------------------------------
async function extractXlsxMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};

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

    // Count sheets
    const workbookXml = await zip.file("xl/workbook.xml")?.async("text");
    if (workbookXml) {
      const wb = parser.parse(workbookXml);
      const sheets = wb?.workbook?.sheets?.sheet;
      if (sheets) {
        metadata.sheetCount = Array.isArray(sheets) ? sheets.length : 1;
        metadata.sheetNames = Array.isArray(sheets)
          ? sheets.map((s) => s["@_name"]).filter(Boolean)
          : [sheets["@_name"]].filter(Boolean);
      }
    }

    // Check for VBA macros
    const vbaProject = zip.file("xl/vbaProject.bin");
    if (vbaProject) {
      notes.push("WARNING: Workbook contains VBA macros (vbaProject.bin).");
      metadata.hasMacros = true;
    }
  } catch (error) {
    notes.push(`XLSX metadata parse failed: ${error.message}`);
  }

  return {
    source: "xlsx",
    metadata,
    notes,
    extractedText: "",
  };
}

// ---------------------------------------------------------------------------
// PPTX (PowerPoint) metadata extraction
// ---------------------------------------------------------------------------
async function extractPptxMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};

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

    // Count slides
    const slideFiles = Object.keys(zip.files).filter(
      (f) => /^ppt\/slides\/slide\d+\.xml$/.test(f)
    );
    metadata.slideCount = slideFiles.length;

    // Check for VBA macros
    const vbaProject = zip.file("ppt/vbaProject.bin");
    if (vbaProject) {
      notes.push("WARNING: Presentation contains VBA macros (vbaProject.bin).");
      metadata.hasMacros = true;
    }
  } catch (error) {
    notes.push(`PPTX metadata parse failed: ${error.message}`);
  }

  return {
    source: "pptx",
    metadata,
    notes,
    extractedText: "",
  };
}

// ---------------------------------------------------------------------------
// SVG metadata + script/XSS detection
// ---------------------------------------------------------------------------
async function extractSvgMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  const content = fileBuffer.toString("utf8");

  try {
    const parser = new XMLParser(XML_OPTIONS);
    const parsed = parser.parse(content);
    const svgRoot = parsed?.svg || {};

    metadata.width = svgRoot["@_width"] || null;
    metadata.height = svgRoot["@_height"] || null;
    metadata.viewBox = svgRoot["@_viewBox"] || null;
    metadata.xmlns = svgRoot["@_xmlns"] || null;

    // Check metadata element
    if (svgRoot.metadata) {
      metadata.svgMetadata = toSerializableValue(svgRoot.metadata);
    }
    if (svgRoot.title) {
      metadata.title = String(svgRoot.title);
    }
    if (svgRoot.desc) {
      metadata.description = String(svgRoot.desc);
    }
  } catch (error) {
    notes.push(`SVG parse failed: ${error.message}`);
  }

  // XSS / script detection
  const xssPatterns = [
    { pattern: /<script[\s>]/i, label: "Embedded <script> tag" },
    { pattern: /\bon\w+\s*=/i, label: "Inline event handler (onclick, onload, etc.)" },
    { pattern: /javascript:/i, label: "javascript: URI scheme" },
    { pattern: /<foreignObject/i, label: "<foreignObject> element (can embed HTML)" },
    { pattern: /xlink:href\s*=\s*["']javascript:/i, label: "xlink:href with javascript: URI" },
    { pattern: /data:text\/html/i, label: "data: URI with text/html" },
    { pattern: /<iframe/i, label: "Embedded <iframe>" },
    { pattern: /<!--.*?(eval|exec|document\.cookie)/i, label: "Suspicious code in SVG comment" },
  ];

  const xssFindings = [];
  for (const { pattern, label } of xssPatterns) {
    if (pattern.test(content)) {
      xssFindings.push(label);
    }
  }

  if (xssFindings.length > 0) {
    metadata.xssRisks = xssFindings;
    notes.push(`XSS RISK: ${xssFindings.length} embedded script/XSS pattern(s) detected.`);
  }

  return {
    source: "svg",
    metadata,
    notes,
    extractedText: content.slice(0, 4000),
  };
}

// ---------------------------------------------------------------------------
// ZIP/RAR archive analysis
// ---------------------------------------------------------------------------
async function extractArchiveMetadata(fileBuffer, extension) {
  const notes = [];
  const metadata = {};

  if (extension === ".rar") {
    return {
      source: "archive",
      metadata: { format: "RAR" },
      notes: ["RAR archive detected. Listing contents requires native unrar. Only ZIP inspection is fully supported."],
      extractedText: "",
    };
  }

  try {
    const zip = await JSZip.loadAsync(fileBuffer);
    const entries = [];
    const suspiciousFiles = [];

    const suspiciousPatterns = [
      { pattern: /\.(exe|bat|cmd|com|scr|pif|msi|vbs|vbe|wsf|wsh|ps1)$/i, label: "Executable file" },
      { pattern: /\.(docm|xlsm|pptm|xlam)$/i, label: "Macro-enabled Office file" },
      { pattern: /\.(js|jse|hta)$/i, label: "Script file" },
      { pattern: /\.\w+\.\w+$/i, label: "Double extension" },
      { pattern: /__MACOSX/i, label: "macOS resource fork" },
      { pattern: /\.(lnk|url)$/i, label: "Shortcut file" },
    ];

    zip.forEach((relativePath, zipEntry) => {
      entries.push({
        name: relativePath,
        size: zipEntry._data?.uncompressedSize || 0,
        dir: zipEntry.dir,
        date: zipEntry.date?.toISOString() || null,
      });

      for (const { pattern, label } of suspiciousPatterns) {
        if (pattern.test(relativePath)) {
          suspiciousFiles.push({ file: relativePath, reason: label });
        }
      }
    });

    metadata.format = "ZIP";
    metadata.totalEntries = entries.length;
    metadata.entries = entries.slice(0, 50); // cap listing
    metadata.suspiciousFiles = suspiciousFiles;

    if (suspiciousFiles.length > 0) {
      notes.push(`WARNING: ${suspiciousFiles.length} suspicious file(s) found in archive.`);
    }
  } catch (error) {
    notes.push(`Archive parse failed: ${error.message}`);
  }

  return {
    source: "archive",
    metadata,
    notes,
    extractedText: "",
  };
}

// ---------------------------------------------------------------------------
// EML (email) metadata + phishing detection
// ---------------------------------------------------------------------------
async function extractEmlMetadata(fileBuffer) {
  const notes = [];
  const metadata = {};
  const content = fileBuffer.toString("utf8");

  try {
    const headers = {};
    const headerSection = content.split(/\r?\n\r?\n/)[0] || "";
    const lines = headerSection.split(/\r?\n/);
    let currentKey = "";

    for (const line of lines) {
      if (/^\s/.test(line) && currentKey) {
        // continuation
        headers[currentKey] += " " + line.trim();
      } else {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          currentKey = line.slice(0, colonIdx).trim().toLowerCase();
          headers[currentKey] = line.slice(colonIdx + 1).trim();
        }
      }
    }

    metadata.from = headers.from || null;
    metadata.to = headers.to || null;
    metadata.cc = headers.cc || null;
    metadata.subject = headers.subject || null;
    metadata.date = headers.date || null;
    metadata.messageId = headers["message-id"] || null;
    metadata.replyTo = headers["reply-to"] || null;
    metadata.returnPath = headers["return-path"] || null;
    metadata.xMailer = headers["x-mailer"] || null;
    metadata.contentType = headers["content-type"] || null;

    // SPF/DKIM/DMARC headers
    metadata.authenticationResults = headers["authentication-results"] || null;
    metadata.receivedSpf = headers["received-spf"] || null;
    metadata.dkimSignature = headers["dkim-signature"] ? "present" : null;

    // Phishing indicators
    const phishingIndicators = [];

    // Check for mismatched from/reply-to
    if (metadata.from && metadata.replyTo) {
      const fromDomain = metadata.from.match(/@([^\s>]+)/)?.[1];
      const replyDomain = metadata.replyTo.match(/@([^\s>]+)/)?.[1];
      if (fromDomain && replyDomain && fromDomain !== replyDomain) {
        phishingIndicators.push("From and Reply-To domains do not match");
      }
    }

    // Check for URL patterns in body
    const bodySection = content.split(/\r?\n\r?\n/).slice(1).join("\n\n");
    const urlMatches = bodySection.match(/https?:\/\/[^\s<>"]+/g) || [];
    const suspiciousUrls = urlMatches.filter((url) => {
      return (
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) || // IP addresses
        /@/.test(url.split("?")[0]) || // @ in URL path
        /bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd|shorturl/i.test(url) || // URL shorteners
        /(verify|confirm|secure|login|signin|account|update|password)/i.test(url) // phishing keywords
      );
    });

    if (suspiciousUrls.length > 0) {
      phishingIndicators.push(`${suspiciousUrls.length} suspicious URL(s) in body`);
      metadata.suspiciousUrls = suspiciousUrls.slice(0, 10);
    }

    // Check for urgency patterns
    const urgencyPatterns = /\b(urgent|immediate action|verify your account|suspend|confirm your identity|click here now|limited time)\b/i;
    if (urgencyPatterns.test(bodySection)) {
      phishingIndicators.push("Urgency/phishing language detected in body");
    }

    if (phishingIndicators.length > 0) {
      metadata.phishingIndicators = phishingIndicators;
      notes.push(`PHISHING RISK: ${phishingIndicators.length} indicator(s) detected.`);
    }
  } catch (error) {
    notes.push(`EML parse failed: ${error.message}`);
  }

  return {
    source: "eml",
    metadata,
    notes,
    extractedText: content.slice(0, 6000),
  };
}

// ---------------------------------------------------------------------------
// Text document extraction
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Local virus heuristics
// ---------------------------------------------------------------------------
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

  // Additional heuristics
  if (/\.(exe|scr|pif|bat|cmd|com|vbs|vbe|wsf|wsh|ps1)$/i.test(originalName)) {
    findings.push({
      severity: "suspicious",
      label: "Executable file extension",
      detail: `File has executable extension: ${extension}`,
    });
  }

  // Check for PE header (Windows executables)
  if (content.startsWith("MZ") && content.includes("PE\x00\x00")) {
    findings.push({
      severity: "suspicious",
      label: "Windows PE executable detected",
      detail: "File contains MZ/PE headers indicating a Windows executable.",
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

// ---------------------------------------------------------------------------
// VirusTotal integration
// ---------------------------------------------------------------------------
async function fetchVirusTotalReport(apiKey, sha256) {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
    headers: { "x-apikey": apiKey },
  });

  if (res.status === 404) return null;

  if (res.status === 429) {
    return {
      _rateLimited: true,
      message: "VirusTotal rate limit reached (4 requests/min on free tier). Try again in 60 seconds.",
    };
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`VirusTotal file lookup failed (${res.status}): ${text.slice(0, 160)}`);
  }

  return await res.json();
}

function formatVirusTotalResponse(payload) {
  const attrs = payload?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};

  // Build engine breakdown
  const engines = attrs.last_analysis_results || {};
  const detectedEngines = [];
  for (const [name, result] of Object.entries(engines)) {
    if (result?.category === "malicious" || result?.category === "suspicious") {
      detectedEngines.push({
        engine: name,
        category: result.category,
        result: result.result || "detected",
      });
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
    totalEngines:
      Number(stats.malicious || 0) +
      Number(stats.suspicious || 0) +
      Number(stats.harmless || 0) +
      Number(stats.undetected || 0) +
      Number(stats.timeout || 0) +
      Number(stats["type-unsupported"] || 0),
    detectedEngines: detectedEngines.slice(0, 30),
    permalink: attrs?.links?.item || payload?.data?.links?.self || null,
    scannedAt: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
    communityScore: attrs.reputation ?? null,
    meaningfulName: attrs.meaningful_name || null,
    typeDescription: attrs.type_description || null,
    tags: (attrs.tags || []).slice(0, 10),
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
    return {
      status: "rate_limited",
      source: "virustotal",
      message: "VirusTotal rate limit reached (4 requests/min on free tier). Try again in 60 seconds.",
    };
  }

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

    if (analysisRes.status === 429) {
      return {
        status: "rate_limited",
        source: "virustotal",
        message: "VirusTotal rate limit reached during polling. Results may be available later.",
      };
    }

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
        message: "VirusTotal API key is not configured. Set the VIRUSTOTAL_API_KEY environment variable to enable cloud-based malware intelligence. Get a free API key at https://www.virustotal.com/gui/join-us",
      },
    };
  }

  try {
    const existingReport = await fetchVirusTotalReport(apiKey, sha256);

    if (existingReport?._rateLimited) {
      return {
        overallStatus: local.status,
        local,
        virustotal: {
          status: "rate_limited",
          source: "virustotal",
          message: existingReport.message,
        },
      };
    }

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

// ---------------------------------------------------------------------------
// Main file analysis
// ---------------------------------------------------------------------------
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
  if (kind === "xlsx") extraction = await extractXlsxMetadata(fileBuffer);
  if (kind === "pptx") extraction = await extractPptxMetadata(fileBuffer);
  if (kind === "svg") extraction = await extractSvgMetadata(fileBuffer);
  if (kind === "archive") extraction = await extractArchiveMetadata(fileBuffer, extension);
  if (kind === "eml") extraction = await extractEmlMetadata(fileBuffer);
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

  // Also scan the filename itself for injection payloads
  const filenameScan = detectPromptInjection(originalName);
  const filenameWarnings = [];
  if (filenameScan.matches.length > 0) {
    filenameWarnings.push(
      `WARNING: Filename contains suspicious prompt injection patterns: ${filenameScan.matches.map((m) => m.id).join(", ")}`
    );
  }

  const scanText = `${extraction.extractedText || ""}\n\n${extraText || ""}`.trim();
  const promptInjection = detectPromptInjection(scanText);

  // Merge filename warnings into notes
  if (filenameWarnings.length > 0) {
    promptInjection.filenameWarnings = filenameWarnings;
  }

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
    notes: [...(extraction.notes || []), ...filenameWarnings],
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
