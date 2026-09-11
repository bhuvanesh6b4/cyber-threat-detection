/**
 * emailScanner.js
 * Real AI detection via Google Gemini when GEMINI_API_KEY is configured
 * (see geminiService.js — key stays backend-only). Otherwise falls back
 * to deterministic sender/subject/body heuristics under "LOCAL DEMO MODE",
 * which is never presented as AI.
 */
const gemini = require('./geminiService');

const FREE_EMAIL_DOMAINS = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'];
const SPOOF_INDICATORS = ['support@', 'admin@', 'security@', 'billing@', 'no-reply@'];
const URGENCY_WORDS = ['urgent', 'immediately', 'now', 'expire', 'suspended', 'action required'];
const CREDENTIAL_WORDS = ['password', 'verify your account', 'confirm your identity', 'ssn', 'otp', 'card number'];
const URL_PATTERN = /https?:\/\/[^\s]+/gi;

function localDemoScan({ sender = '', subject = '', body = '' }) {
  const lowerSender = sender.toLowerCase();
  const lowerSubject = subject.toLowerCase();
  const lowerBody = body.toLowerCase();
  const combined = `${lowerSubject} ${lowerBody}`;

  let score = 5;
  const reasons = [];

  const senderDomain = lowerSender.split('@')[1] || '';
  const looksLikeBrandButFreeMail = SPOOF_INDICATORS.some((p) => lowerSender.startsWith(p))
    && FREE_EMAIL_DOMAINS.includes(senderDomain);

  if (looksLikeBrandButFreeMail) {
    score += 25;
    reasons.push(`Sender looks like an official address but uses a free email domain (${senderDomain}) — possible spoofing.`);
  }

  if (senderDomain && FREE_EMAIL_DOMAINS.includes(senderDomain) && /bank|support|security|billing/.test(lowerSubject)) {
    score += 15;
    reasons.push('Sensitive-sounding subject sent from a free email provider.');
  }

  CREDENTIAL_WORDS.forEach((w) => {
    if (combined.includes(w)) {
      score += 15;
      reasons.push(`Requests sensitive information: "${w}"`);
    }
  });

  const urgencyHits = URGENCY_WORDS.filter((w) => combined.includes(w));
  if (urgencyHits.length > 0) {
    score += urgencyHits.length * 6;
    reasons.push(`Urgency-based language detected: ${urgencyHits.join(', ')}`);
  }

  const links = body.match(URL_PATTERN) || [];
  if (links.length > 0) {
    score += 10;
    reasons.push(`Email contains ${links.length} embedded link(s).`);
  }

  if (!sender.includes('@')) {
    score += 10;
    reasons.push('Sender address is malformed or missing a domain.');
  }

  score = Math.min(score, 100);

  let status = 'SAFE';
  if (score >= 65) status = 'MALICIOUS';
  else if (score >= 30) status = 'SUSPICIOUS';

  if (reasons.length === 0) {
    reasons.push('No suspicious sender, subject, or body patterns matched by local rules.');
  }

  const recommendations = {
    SAFE: 'No strong phishing indicators found in this email.',
    SUSPICIOUS: 'Some red flags present. Verify the sender through a separate channel before acting.',
    MALICIOUS: 'High-confidence phishing indicators. Do not click links or reply with information.'
  };

  return {
    status,
    threatScore: score,
    threatType: status === 'SAFE' ? 'None detected' : 'Email Phishing / Spoofing',
    confidence: 68,
    source: 'LOCAL DEMO MODE (rule-based, not AI)',
    reasons,
    recommendation: recommendations[status]
  };
}

function buildPrompt({ sender, subject, body }) {
  return `You are a cybersecurity threat-detection assistant. Analyze the email below for phishing, spoofing, business email compromise, or other malicious intent. Pay attention to sender/domain mismatches, urgency tactics, and credential or payment requests.

Respond with ONLY a raw JSON object — no markdown, no code fences, no extra commentary — in exactly this shape:
{
  "status": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "threatScore": <integer 0-100, higher = more dangerous>,
  "threatType": "<short label, e.g. 'Phishing', 'Spoofing', 'Business Email Compromise', or 'None detected'>",
  "confidence": <integer 0-100>,
  "reasons": ["<short specific reason>", "..."],
  "recommendation": "<one or two sentence actionable recommendation>"
}

Email to analyze:
Sender: ${sender}
Subject: ${subject}
Body:
"""
${body}
"""`;
}

async function scanEmail(emailFields) {
  if (gemini.isConfigured()) {
    try {
      const result = await gemini.callGemini(buildPrompt(emailFields));
      return { ...result, source: 'Google Gemini AI' };
    } catch (err) {
      console.error('[emailScanner] Gemini failed, falling back to LOCAL DEMO MODE:', err.message);
      const demo = localDemoScan(emailFields);
      demo.reasons.unshift(`Gemini API unavailable (${err.message}) — showing LOCAL DEMO MODE result instead.`);
      return demo;
    }
  }
  return localDemoScan(emailFields);
}

module.exports = { scanEmail };
