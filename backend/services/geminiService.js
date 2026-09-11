/**
 * geminiService.js
 * Single shared client for Google Gemini API calls, used by both
 * textScanner.js and emailScanner.js. The API key is read ONLY from
 * process.env on the backend — it is never sent to or reachable from
 * the frontend.
 *
 * Requires GEMINI_API_KEY in backend/.env.
 * Get a key at: https://aistudio.google.com/app/apikey
 */
const fetch = require('node-fetch');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
// Model is overridable via GEMINI_MODEL so it can be updated (e.g. after
// Google deprecates a version) without touching code — just change .env.
// gemini-3.6-flash is the current GA production model as of this writing.
// Google's models change over time; if you see deprecation warnings, check
// https://ai.google.dev/gemini-api/docs/models for the current recommended
// replacement and update GEMINI_MODEL in backend/.env.
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

const ALLOWED_STATUSES = ['SAFE', 'SUSPICIOUS', 'MALICIOUS'];

function isConfigured() {
  return Boolean(GEMINI_API_KEY);
}

/**
 * Calls Gemini with a prompt that instructs it to return ONLY JSON,
 * and forces JSON output via responseMimeType so we don't have to
 * strip markdown code fences.
 */
async function callGemini(prompt) {
  if (!isConfigured()) {
    const err = new Error('GEMINI_API_KEY is not configured on the backend.');
    err.code = 'GEMINI_NOT_CONFIGURED';
    throw err;
  }

  let response;
  try {
    response = await fetch(`${GEMINI_URL}?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: 'application/json'
        }
      })
    });
  } catch (networkErr) {
    throw new Error(`Could not reach Gemini API: ${networkErr.message}`);
  }

  if (!response.ok) {
    let detail = '';
    try {
      const errBody = await response.json();
      detail = errBody?.error?.message || '';
    } catch { /* ignore parse failure */ }
    throw new Error(`Gemini API error ${response.status}${detail ? `: ${detail}` : ''}`);
  }

  const data = await response.json();

  const blockReason = data.promptFeedback?.blockReason;
  if (blockReason) {
    throw new Error(`Gemini blocked this request (${blockReason}).`);
  }

  const candidate = data.candidates && data.candidates[0];
  const rawText = candidate?.content?.parts?.[0]?.text;

  if (!rawText) {
    throw new Error('Gemini API returned an empty or unexpected response.');
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new Error('Gemini API response could not be parsed as JSON.');
  }

  return normalizeResult(parsed);
}

/**
 * Clamps/defaults whatever Gemini returned into the exact structured
 * shape the rest of the app expects, so a malformed model response
 * can never crash a route or corrupt a Sheets row.
 */
function normalizeResult(parsed) {
  const clamp = (value, fallback) => {
    const num = Number(value);
    if (Number.isNaN(num)) return fallback;
    return Math.max(0, Math.min(100, Math.round(num)));
  };

  const status = ALLOWED_STATUSES.includes(String(parsed.status || '').toUpperCase())
    ? String(parsed.status).toUpperCase()
    : 'SUSPICIOUS';

  const reasons = Array.isArray(parsed.reasons) && parsed.reasons.length
    ? parsed.reasons.slice(0, 8).map((r) => String(r).slice(0, 300))
    : ['Gemini did not provide detailed reasons for this verdict.'];

  return {
    status,
    threatScore: clamp(parsed.threatScore, 50),
    threatType: (typeof parsed.threatType === 'string' && parsed.threatType.trim())
      ? parsed.threatType.trim().slice(0, 100)
      : 'Unclassified',
    confidence: clamp(parsed.confidence, 50),
    reasons,
    recommendation: (typeof parsed.recommendation === 'string' && parsed.recommendation.trim())
      ? parsed.recommendation.trim().slice(0, 500)
      : 'Review this content manually before taking any action.'
  };
}

module.exports = { callGemini, isConfigured };
