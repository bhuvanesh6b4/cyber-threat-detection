const express = require('express');
const multer = require('multer');
const crypto = require('crypto');

const { scanUrl } = require('../services/urlScanner');
const { scanText } = require('../services/textScanner');
const { scanEmail } = require('../services/emailScanner');
const { scanFile } = require('../services/fileScanner');
const sheetsService = require('../services/sheetsService');
const {
  isValidUrl, isNonEmptyString, sanitizeText, isAllowedFileType, ALLOWED_FILE_EXTENSIONS
} = require('../utils/validation');

const router = express.Router();

// Memory storage only — files are NEVER written to disk or executed.
const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB || 5);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 }
});

function generateScanId() {
  return `SCN-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

/**
 * Persists the result to Google Sheets. If Sheets isn't configured or the
 * write fails, the scan result is still returned to the user — but the
 * response clearly flags that it was NOT saved, so nothing is silently lost.
 */
async function persistResult({ inputType, inputSummary, result }) {
  const record = {
    scanId: generateScanId(),
    timestamp: new Date().toISOString(),
    inputType,
    input: inputSummary,
    status: result.status,
    threatScore: result.threatScore,
    threatType: result.threatType,
    confidence: result.confidence,
    detectionSource: result.source,
    recommendation: result.recommendation
  };

  try {
    await sheetsService.saveScanRecord(record);
    return { saved: true, scanId: record.scanId };
  } catch (err) {
    console.error('[scan] Failed to save to Google Sheets:', err.message);
    return { saved: false, scanId: record.scanId, saveError: err.message };
  }
}

// ---------------- URL Scanner ----------------
router.post('/url', async (req, res, next) => {
  try {
    const { url } = req.body;

    if (!isValidUrl(url)) {
      return res.status(400).json({ success: false, error: 'Please provide a valid http(s) URL.' });
    }

    const result = await scanUrl(url.trim());
    const persistence = await persistResult({
      inputType: 'URL', inputSummary: url.trim(), result
    });

    res.json({
      success: true,
      data: { ...result, ...persistence, scannedAt: new Date().toISOString() }
    });
  } catch (err) {
    next(err);
  }
});

// ---------------- Text Scanner ----------------
router.post('/text', async (req, res, next) => {
  try {
    const { text } = req.body;

    if (!isNonEmptyString(text)) {
      return res.status(400).json({ success: false, error: 'Please provide non-empty text (max 20,000 characters).' });
    }

    const clean = sanitizeText(text);
    const result = await scanText(clean);
    const persistence = await persistResult({
      inputType: 'TEXT',
      inputSummary: clean.length > 120 ? `${clean.slice(0, 120)}…` : clean,
      result
    });

    res.json({
      success: true,
      data: { ...result, ...persistence, scannedAt: new Date().toISOString() }
    });
  } catch (err) {
    next(err);
  }
});

// ---------------- Email Scanner ----------------
router.post('/email', async (req, res, next) => {
  try {
    const { sender, subject, body } = req.body;

    if (!isNonEmptyString(sender, 320) || !isNonEmptyString(subject, 500) || !isNonEmptyString(body)) {
      return res.status(400).json({
        success: false,
        error: 'Please provide sender, subject, and body — all required.'
      });
    }

    const result = await scanEmail({
      sender: sanitizeText(sender),
      subject: sanitizeText(subject),
      body: sanitizeText(body)
    });

    const persistence = await persistResult({
      inputType: 'EMAIL',
      inputSummary: `From: ${sender.trim()} | Subject: ${subject.trim()}`,
      result
    });

    res.json({
      success: true,
      data: { ...result, ...persistence, scannedAt: new Date().toISOString() }
    });
  } catch (err) {
    next(err);
  }
});

// ---------------- File Scanner ----------------
router.post('/file', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded (field name must be "file").' });
    }

    const { originalname, size, buffer } = req.file;

    if (!isAllowedFileType(originalname)) {
      return res.status(400).json({
        success: false,
        error: `File type not allowed. Allowed: ${ALLOWED_FILE_EXTENSIONS.join(' ')}`
      });
    }

    if (size > MAX_FILE_SIZE_MB * 1024 * 1024) {
      return res.status(400).json({ success: false, error: `File exceeds ${MAX_FILE_SIZE_MB}MB limit.` });
    }

    const result = await scanFile(buffer, originalname);
    // buffer goes out of scope here and is garbage collected — never written to disk.

    const persistence = await persistResult({
      inputType: 'FILE',
      inputSummary: `${originalname} (${(size / 1024).toFixed(1)} KB, sha256: ${result.sha256?.slice(0, 12)}…)`,
      result
    });

    res.json({
      success: true,
      data: { ...result, ...persistence, filename: originalname, scannedAt: new Date().toISOString() }
    });
  } catch (err) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, error: `File exceeds ${MAX_FILE_SIZE_MB}MB limit.` });
    }
    next(err);
  }
});

module.exports = router;
