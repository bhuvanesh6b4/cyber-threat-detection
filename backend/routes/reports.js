const express = require('express');
const sheetsService = require('../services/sheetsService');

const router = express.Router();

// GET /api/reports  -> all scan records (optionally filtered)
router.get('/', async (req, res, next) => {
  try {
    if (!sheetsService.isConfigured()) {
      return res.json({
        success: true,
        data: [],
        warning: 'Google Sheets is not configured yet. No scan data available.'
      });
    }

    const records = await sheetsService.getAllScanRecords();

    const { status, search } = req.query;
    let filtered = records;

    if (status && status.toUpperCase() !== 'ALL') {
      filtered = filtered.filter((r) => (r.status || '').toUpperCase() === status.toUpperCase());
    }

    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter((r) =>
        JSON.stringify(r).toLowerCase().includes(q));
    }

    // Most recent first
    filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, data: filtered });
  } catch (err) {
    next(err);
  }
});

// GET /api/reports/:id -> single scan record
router.get('/:id', async (req, res, next) => {
  try {
    if (!sheetsService.isConfigured()) {
      return res.status(503).json({ success: false, error: 'Google Sheets is not configured yet.' });
    }
    const record = await sheetsService.getScanRecordById(req.params.id);
    if (!record) {
      return res.status(404).json({ success: false, error: 'Scan record not found.' });
    }
    res.json({ success: true, data: record });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
