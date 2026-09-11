/**
 * sheetsService.js
 * All communication with the Google Sheet happens through the
 * Google Apps Script Web App URL (GOOGLE_APPS_SCRIPT_URL).
 * This keeps Google credentials completely off the frontend and
 * lets the Sheet act as a simple free database for the project.
 *
 * IMPORTANT FAILURE MODE THIS FILE GUARDS AGAINST:
 * Apps Script Web Apps return an HTML page (not JSON) at the PLATFORM
 * level — before your Code.gs even runs — when either:
 *   (a) the deployed URL is the /dev URL instead of /exec, or
 *   (b) the deployment's "Who has access" is not set to "Anyone".
 * A raw `response.json()` call would throw a cryptic
 * "Unexpected token '<'" error in that case. Every function below reads
 * the body as text first and detects this specific failure mode to
 * produce an actionable error message instead.
 */
const fetch = require('node-fetch');

const SHEETS_URL = process.env.GOOGLE_APPS_SCRIPT_URL;

if (SHEETS_URL && SHEETS_URL.includes('/dev')) {
  console.warn(
    '[sheetsService] WARNING: GOOGLE_APPS_SCRIPT_URL looks like a /dev URL. ' +
    'Server-to-server requests cannot authenticate against /dev (it requires ' +
    'an active Google login session) and will receive an HTML sign-in page ' +
    'instead of JSON. Deploy the script and use the /exec URL instead.'
  );
}

function assertConfigured() {
  if (!SHEETS_URL) {
    const err = new Error(
      'Google Sheets is not configured. Set GOOGLE_APPS_SCRIPT_URL in backend/.env'
    );
    err.status = 503;
    throw err;
  }
}

/**
 * Reads a fetch Response as text, then safely parses it as JSON.
 * If the body isn't valid JSON (most commonly an HTML page returned by
 * the Apps Script platform itself), throws a specific, actionable error
 * instead of the raw "Unexpected token '<'" parse error.
 */
async function parseAppsScriptResponse(response) {
  const rawText = await response.text();
  const trimmed = rawText.trim();

  const looksLikeHtml = trimmed.startsWith('<');

  if (looksLikeHtml) {
    const isDevUrl = SHEETS_URL.includes('/dev');
    throw new Error(
      'Google Apps Script returned an HTML page instead of JSON, which means the ' +
      'request never reached your Code.gs — it was rejected by the Apps Script ' +
      'platform itself. This almost always means one of: ' +
      (isDevUrl ? '(1) GOOGLE_APPS_SCRIPT_URL is a /dev URL — redeploy and use the /exec URL instead. ' : '(1) the URL looks like /exec, so check the next causes. ') +
      '(2) the deployment\'s "Who has access" is not set to "Anyone". ' +
      '(3) the deployment is stale — after editing Code.gs you must create a ' +
      'new deployment version (Manage deployments -> Edit -> New version). ' +
      'See README.md section "Troubleshooting: HTML instead of JSON" for exact steps.'
    );
  }

  if (!response.ok) {
    throw new Error(`Google Sheets request failed with HTTP status ${response.status}: ${trimmed.slice(0, 200)}`);
  }

  let data;
  try {
    data = JSON.parse(trimmed);
  } catch {
    throw new Error(`Google Apps Script returned a response that isn't valid JSON: ${trimmed.slice(0, 200)}`);
  }

  return data;
}

/**
 * Saves one scan record as a new row in the Google Sheet.
 * record shape must match the columns defined in Code.gs.
 */
async function saveScanRecord(record) {
  assertConfigured();

  const response = await fetch(SHEETS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'create', record }),
    redirect: 'follow'
  });

  const data = await parseAppsScriptResponse(response);
  if (!data.success) {
    throw new Error(data.error || 'Google Sheets rejected the write');
  }
  return data.data; // the saved record, including generated Scan ID
}

/**
 * Fetches all scan records from the Sheet (used by /api/reports and /api/stats).
 */
async function getAllScanRecords() {
  assertConfigured();

  const response = await fetch(`${SHEETS_URL}?action=list`, { redirect: 'follow' });
  const data = await parseAppsScriptResponse(response);
  if (!data.success) {
    throw new Error(data.error || 'Google Sheets rejected the read');
  }
  return data.data || [];
}

/**
 * Fetches a single scan record by Scan ID.
 */
async function getScanRecordById(scanId) {
  assertConfigured();

  const response = await fetch(`${SHEETS_URL}?action=get&id=${encodeURIComponent(scanId)}`, { redirect: 'follow' });
  const data = await parseAppsScriptResponse(response);
  if (!data.success) {
    throw new Error(data.error || 'Record not found');
  }
  return data.data;
}

/**
 * Pings the Apps Script deployment directly — useful for isolating
 * whether a problem is the deployment itself vs. the backend's usage of it.
 */
async function pingAppsScript() {
  assertConfigured();
  const response = await fetch(`${SHEETS_URL}?action=ping`, { redirect: 'follow' });
  const data = await parseAppsScriptResponse(response);
  return data;
}

module.exports = {
  saveScanRecord,
  getAllScanRecords,
  getScanRecordById,
  pingAppsScript,
  isConfigured: () => Boolean(SHEETS_URL)
};
