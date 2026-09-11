/**
 * fileScanner.js
 * Files are handled entirely in memory (multer memoryStorage in the route)
 * and are NEVER written to disk and NEVER executed.
 *
 * When VIRUSTOTAL_API_KEY is set: computes the file's SHA-256 hash and
 * looks it up against VirusTotal's existing reports (instant). If VT has
 * no report yet, the file is submitted for analysis and the response
 * clearly explains the result is pending (VT analysis is asynchronous
 * and can take time — not something a single HTTP request can wait for).
 *
 * Otherwise falls back to a LOCAL DEMO MODE based on filename/
 * extension/size heuristics only. This never inspects file content as
 * "malware analysis" — it is explicitly a demo.
 */
const crypto = require('crypto');
const fetch = require('node-fetch');
const FormData = require('form-data');

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';

// NOTE: executable/script extensions (.exe .bat .cmd .scr .js .vbs .jar .msi
// etc.) are already rejected by isAllowedFileType() in utils/validation.js
// BEFORE a file ever reaches this scanner — see routes/scan.js. This
// function intentionally only scores files within that already-safe
// allow-list; it does not — and cannot — re-check extensions the API
// boundary has already blocked. That would be dead code pretending to
// demonstrate detection it can never actually run.
const ARCHIVE_EXTENSIONS = ['.zip'];
const MAX_REASONABLE_SIZE_FOR_TEXT_DOC = 2 * 1024 * 1024; // 2MB

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function virusTotalLookup(hash) {
  const res = await fetch(`${VT_BASE}/files/${hash}`, {
    headers: { 'x-apikey': VT_API_KEY }
  });

  if (res.status === 404) return null; // no existing report
  if (!res.ok) throw new Error(`VirusTotal lookup failed: ${res.status}`);

  const data = await res.json();
  const stats = data.data.attributes.last_analysis_stats;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

  const score = Math.min(Math.round(((malicious * 2 + suspicious) / (totalEngines || 1)) * 100), 100);
  let status = 'SAFE';
  if (malicious > 0) status = 'MALICIOUS';
  else if (suspicious > 0) status = 'SUSPICIOUS';

  return {
    status,
    threatScore: score,
    threatType: status === 'SAFE' ? 'None detected' : 'Malware (see engine detections)',
    confidence: 95,
    source: 'VirusTotal API',
    reasons: [`${malicious} of ${totalEngines} engines flagged this file as malicious, ${suspicious} as suspicious.`],
    recommendation: status === 'SAFE'
      ? 'No known threats found. Still exercise standard caution with any downloaded file.'
      : 'Do not open this file. Quarantine or delete it immediately.'
  };
}

async function virusTotalSubmit(buffer, filename) {
  const form = new FormData();
  form.append('file', buffer, filename);

  const res = await fetch(`${VT_BASE}/files`, {
    method: 'POST',
    headers: { 'x-apikey': VT_API_KEY },
    body: form
  });

  if (!res.ok) throw new Error(`VirusTotal submission failed: ${res.status}`);

  return {
    status: 'SUSPICIOUS',
    threatScore: 40,
    threatType: 'Analysis pending',
    confidence: 30,
    source: 'VirusTotal API (analysis queued)',
    reasons: [
      'This file has not been analyzed by VirusTotal before.',
      'It has been submitted for analysis, which runs asynchronously and can take a few minutes.',
      'Treat as unverified until a follow-up scan is run.'
    ],
    recommendation: 'Treat as unverified. Re-scan later or check the file manually on virustotal.com using its hash.'
  };
}

function localDemoScan(filename, size) {
  const lower = filename.toLowerCase();
  let score = 5;
  const reasons = [];

  const isArchive = ARCHIVE_EXTENSIONS.some((ext) => lower.endsWith(ext));
  if (isArchive) {
    score += 20;
    reasons.push('Archive file (.zip) — contents are not inspected in LOCAL DEMO MODE; archives can conceal any file type.');
  }

  if (size === 0) {
    score += 20;
    reasons.push('File is empty (0 bytes) — unusual and often invalid.');
  }

  if (!isArchive && size > MAX_REASONABLE_SIZE_FOR_TEXT_DOC) {
    score += 10;
    reasons.push('File is unusually large for a document/text/image file of this type.');
  }

  // Double extension within the allowed set (e.g. "resume.docx.pdf") can
  // still indicate a renamed/mislabeled file, even when every extension
  // involved is individually on the allow-list.
  const extensionCount = (lower.match(/\.[a-z0-9]{2,4}/g) || []).length;
  if (extensionCount >= 2) {
    score += 10;
    reasons.push('Filename contains multiple file extensions — verify this is the expected file type.');
  }

  score = Math.min(score, 100);

  let status = 'SAFE';
  if (score >= 55) status = 'SUSPICIOUS';
  if (score >= 80) status = 'MALICIOUS';

  if (reasons.length === 0) {
    reasons.push('No suspicious filename or size patterns matched by local rules.');
  }

  return {
    status,
    threatScore: score,
    threatType: status === 'SAFE' ? 'None detected' : 'Suspicious file characteristics',
    confidence: 50,
    source: 'LOCAL DEMO MODE (rule-based, content not inspected)',
    reasons,
    recommendation: status === 'SAFE'
      ? 'No red flags found by filename/size heuristics. This does NOT guarantee the file is safe — content was not scanned.'
      : 'Exercise caution. This file has not been verified by a real antivirus engine — configure VIRUSTOTAL_API_KEY for real detection.'
  };
}

async function scanFile(buffer, filename) {
  const hash = sha256(buffer);

  if (VT_API_KEY) {
    try {
      const existing = await virusTotalLookup(hash);
      const result = existing || await virusTotalSubmit(buffer, filename);
      return { ...result, sha256: hash };
    } catch (err) {
      console.error('[fileScanner] VirusTotal failed, falling back to demo mode:', err.message);
      const demo = localDemoScan(filename, buffer.length);
      demo.reasons.unshift(`VirusTotal API unavailable (${err.message}) — showing LOCAL DEMO MODE result instead.`);
      return { ...demo, sha256: hash };
    }
  }

  return { ...localDemoScan(filename, buffer.length), sha256: hash };
}

module.exports = { scanFile };
