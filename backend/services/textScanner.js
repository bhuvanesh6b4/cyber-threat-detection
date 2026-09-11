/**
 * textScanner.js
 * Real AI detection via Google Gemini when GEMINI_API_KEY is configured
 * (see geminiService.js — the key never leaves the backend). Otherwise
 * falls back to a deterministic "LOCAL DEMO MODE" (keyword/pattern rules)
 * that is never presented as AI anywhere in the response.
 */
const gemini = require('./geminiService');

const PHISHING_PHRASES = [
  'verify your account', 'confirm your password', 'click here immediately',
  'your account will be suspended', 'urgent action required', 'act now',
  'you have won', 'claim your prize', 'wire transfer', 'gift card',
  'update your billing', 'unusual login activity', 'suspended account'
];

const CREDENTIAL_REQUEST_PATTERNS = [
  'enter your password', 'ssn', 'social security number', 'otp', 'one time password',
  'card number', 'cvv', 'pin number'
];

const URGENCY_WORDS = ['urgent', 'immediately', 'now', 'expire', 'expires', 'asap', 'warning', 'alert'];
const URL_PATTERN = /https?:\/\/[^\s]+/gi;

function localDemoScan(text) {
  const lower = text.toLowerCase();
  let score = 5;
  const reasons = [];

  PHISHING_PHRASES.forEach((phrase) => {
    if (lower.includes(phrase)) {
      score += 15;
      reasons.push(`Contains common phishing phrase: "${phrase}"`);
    }
  });

  CREDENTIAL_REQUEST_PATTERNS.forEach((p) => {
    if (lower.includes(p)) {
      score += 20;
      reasons.push(`Requests sensitive credential information ("${p}")`);
    }
  });

  const urgencyHits = URGENCY_WORDS.filter((w) => lower.includes(w));
  if (urgencyHits.length > 0) {
    score += urgencyHits.length * 5;
    reasons.push(`Uses urgency-based language: ${urgencyHits.join(', ')}`);
  }

  const links = text.match(URL_PATTERN) || [];
  if (links.length > 0) {
    score += 10;
    reasons.push(`Contains ${links.length} embedded link(s) — verify destination before clicking.`);
  }

  if (/\$\d|money|payment|invoice/i.test(text)) {
    score += 8;
    reasons.push('Mentions money/payment — common in scam messages.');
  }

  score = Math.min(score, 100);

  let status = 'SAFE';
  if (score >= 65) status = 'MALICIOUS';
  else if (score >= 30) status = 'SUSPICIOUS';

  if (reasons.length === 0) {
    reasons.push('No suspicious keywords or patterns matched by local rules.');
  }

  const recommendations = {
    SAFE: 'No strong indicators found. Still verify sender identity for sensitive requests.',
    SUSPICIOUS: 'Message shows some red flags. Do not act on it without independently verifying the sender.',
    MALICIOUS: 'High-confidence phishing/scam indicators found. Do not click links or share information.'
  };

  return {
    status,
    threatScore: score,
    threatType: status === 'SAFE' ? 'None detected' : 'Phishing / Social Engineering',
    confidence: 65,
    source: 'LOCAL DEMO MODE (rule-based, not AI)',
    reasons,
    recommendation: recommendations[status]
  };
}

function buildPrompt(text) {
  return `You are a cybersecurity threat-detection assistant. Analyze the text below for phishing, scam, social engineering, malware-distribution, or other malicious intent.

Respond with ONLY a raw JSON object — no markdown, no code fences, no extra commentary — in exactly this shape:
{
  "status": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "threatScore": <integer 0-100, higher = more dangerous>,
  "threatType": "<short label, e.g. 'Phishing', 'Scam', 'Social Engineering', or 'None detected'>",
  "confidence": <integer 0-100>,
  "reasons": ["<short specific reason>", "..."],
  "recommendation": "<one or two sentence actionable recommendation>"
}

Text to analyze:
"""
${text}
"""`;
}

async function scanText(text) {
  if (gemini.isConfigured()) {
    try {
      const result = await gemini.callGemini(buildPrompt(text));
      return { ...result, source: 'Google Gemini AI' };
    } catch (err) {
      console.error('[textScanner] Gemini failed, falling back to LOCAL DEMO MODE:', err.message);
      const demo = localDemoScan(text);
      demo.reasons.unshift(`Gemini API unavailable (${err.message}) — showing LOCAL DEMO MODE result instead.`);
      return demo;
    }
  }
  return localDemoScan(text);
}

module.exports = { scanText };
