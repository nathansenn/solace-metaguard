# GuardianScan

Web tool for:
- Image/document metadata inspection
- Virus scan (local heuristics + optional VirusTotal)
- AI prompt injection detection

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Environment variables

- `PORT` (optional): server port
- `VIRUSTOTAL_API_KEY` (optional): enables cloud malware intelligence

Without `VIRUSTOTAL_API_KEY`, malware checks still run through local heuristics.
