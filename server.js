import express from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import { mkdir, unlink } from "fs/promises";
import { analyzeUploadedFile, detectPromptInjection } from "./src/analyzer.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const UPLOAD_DIR = path.join(__dirname, "uploads");
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB for archives

await mkdir(UPLOAD_DIR, { recursive: true });

const upload = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
  },
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "metadata-guardian-tool",
    version: "2.0.0",
    scannerMode: process.env.VIRUSTOTAL_API_KEY?.trim()
      ? "local+virustotal"
      : "local-only",
    virustotalConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY?.trim()),
    injectionRules: 30,
    supportedFormats: [
      "images (EXIF)", "PDF", "DOCX", "XLSX", "PPTX",
      "SVG (XSS detection)", "ZIP archives", "EML (phishing detection)",
      "text files", "legacy .doc"
    ],
    time: new Date().toISOString(),
  });
});

app.post("/api/prompt-scan", (req, res) => {
  const text = typeof req.body?.text === "string" ? req.body.text : "";
  if (!text.trim()) {
    res.status(400).json({ ok: false, error: "Text is required for prompt scan." });
    return;
  }

  const result = detectPromptInjection(text);
  res.json({ ok: true, promptInjection: result });
});

app.post("/api/analyze", upload.single("file"), async (req, res) => {
  const uploaded = req.file;
  const extraText = typeof req.body?.extraText === "string" ? req.body.extraText : "";

  if (!uploaded) {
    res.status(400).json({ ok: false, error: "File upload is required." });
    return;
  }

  try {
    const analysis = await analyzeUploadedFile(uploaded, extraText);
    res.json({ ok: true, ...analysis });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : "Analysis failed.",
    });
  } finally {
    await unlink(uploaded.path).catch(() => {});
  }
});

app.use((err, _req, res, _next) => {
  if (err?.code === "LIMIT_FILE_SIZE") {
    res.status(400).json({
      ok: false,
      error: `File is too large. Max size is ${MAX_UPLOAD_BYTES / (1024 * 1024)}MB.`,
    });
    return;
  }

  res.status(500).json({
    ok: false,
    error: err?.message || "Unexpected server error.",
  });
});

app.listen(PORT, () => {
  console.log(`metadata-guardian-tool v2.0.0 listening on :${PORT}`);
  console.log(`  Injection rules: 30`);
  console.log(`  File types: images, PDF, DOCX, XLSX, PPTX, SVG, ZIP, EML, text`);
  console.log(`  VirusTotal: ${process.env.VIRUSTOTAL_API_KEY?.trim() ? "enabled" : "not configured"}`);
});
