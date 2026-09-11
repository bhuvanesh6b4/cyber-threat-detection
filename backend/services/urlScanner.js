/**
 * urlScanner.js
 * Real check via VirusTotal API v3 when VIRUSTOTAL_API_KEY is configured.
 * Looks up the URL's existing report first (instant); if VirusTotal has
 * never seen it, submits it for analysis and clearly flags the result as
 * pending. Otherwise falls back to a deterministic "LOCAL DEMO MODE"
 * (rule-based heuristics — NOT a real threat intelligence verdict).
 */
const fetch = require('node-fetch');

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'confirm',
  'bank', 'password', 'signin', 'wallet', 'urgent'
];
const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click'];

function urlToVtId(url) {
  // VirusTotal v3 identifies URLs by URL-safe base64 (no padding) of the raw URL.
  return Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function virusTotalLookup(url) {
  const id = urlToVtId(url);
  const res = await fetch(`${VT_BASE}/urls/${id}`, {
    headers: { 'x-apikey': VT_API_KEY }
  });

  if (res.status === 404) return null; // never scanned before
  if (!res.ok) throw new Error(`VirusTotal URL lookup failed: ${res.status}`);

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
    threatType: status === 'SAFE' ? 'None detected' : 'Malicious URL (see engine detections)',
    confidence: 95,
    source: 'VirusTotal API',
    reasons: [`${malicious} of ${totalEngines} engines flagged this URL as malicious, ${suspicious} as suspicious.`],
    recommendation: status === 'SAFE'
      ? 'No known threats found. Still exercise standard caution with any external link.'
      : 'Do not visit this URL or enter any information on it.'
  };
}

async function virusTotalSubmit(url) {
  const form = new URLSearchParams();
  form.append('url', url);

  const res = await fetch(`${VT_BASE}/urls`, {
    method: 'POST',
    headers: {
      'x-apikey': VT_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: form.toString()
  });

  if (!res.ok) throw new Error(`VirusTotal URL submission failed: ${res.status}`);

  return {
    status: 'SUSPICIOUS',
    threatScore: 40,
    threatType: 'Analysis pending',
    confidence: 30,
    source: 'VirusTotal API (analysis queued)',
    reasons: [
      'This URL has not been analyzed by VirusTotal before.',
      'It has been submitted for analysis, which runs asynchronously and can take a few minutes.',
      'Treat as unverified until a follow-up scan is run.'
    ],
    recommendation: 'Treat as unverified. Re-check later on virustotal.com or re-run this scan in a few minutes.'
  };
}

/** LOCAL DEMO MODE — deterministic heuristic scoring, not a real verdict. */
function localDemoScan(rawUrl) {
  const url = rawUrl.toLowerCase();
  let score = 5;
  const reasons = [];

  let hostname = '';
  try { hostname = new URL(rawUrl).hostname; } catch { hostname = ''; }

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
    score += 35;
    reasons.push('URL uses a raw IP address instead of a domain name.');
  }

  SUSPICIOUS_KEYWORDS.forEach((kw) => {
    if (url.includes(kw)) {
      score += 8;
      reasons.push(`Contains sensitive keyword "${kw}" often used in phishing URLs.`);
    }
  });

  SUSPICIOUS_TLDS.forEach((tld) => {
    if (hostname.endsWith(tld)) {
      score += 20;
      reasons.push(`Uses a top-level domain (${tld}) frequently abused for phishing.`);
    }
  });

  if ((hostname.match(/-/g) || []).length >= 3) {
    score += 10;
    reasons.push('Domain contains multiple hyphens, a common typosquatting pattern.');
  }

  if (hostname.length > 40) {
    score += 10;
    reasons.push('Unusually long domain name.');
  }

  if (!url.startsWith('https://')) {
    score += 10;
    reasons.push('Connection is not secured with HTTPS.');
  }

  score = Math.min(score, 100);

  let status = 'SAFE';
  if (score >= 70) status = 'MALICIOUS';
  else if (score >= 35) status = 'SUSPICIOUS';

  if (reasons.length === 0) {
    reasons.push('No suspicious patterns matched by local heuristic rules.');
  }

  const recommendations = {
    SAFE: 'No obvious red flags found by local rules. Still exercise normal caution.',
    SUSPICIOUS: 'Treat with caution. Verify sender/source before clicking or entering data.',
    MALICIOUS: 'Do not open the link or provide personal information.'
  };

  return {
    status,
    threatScore: score,
    threatType: status === 'SAFE' ? 'None detected' : 'Suspicious URL pattern',
    confidence: 70,
    source: 'LOCAL DEMO MODE (rule-based, not AI)',
    reasons,
    recommendation: recommendations[status]
  };
}

async function scanUrl(url) {
  if (VT_API_KEY) {
    try {
      const existing = await virusTotalLookup(url);
      return existing || await virusTotalSubmit(url);
    } catch (err) {
      console.error('[urlScanner] VirusTotal failed, falling back to LOCAL DEMO MODE:', err.message);
      const demo = localDemoScan(url);
      demo.reasons.unshift(`VirusTotal API unavailable (${err.message}) — showing LOCAL DEMO MODE result instead.`);
      return demo;
    }
  }
  return localDemoScan(url);
}

module.exports = { scanUrl };
