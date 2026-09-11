const express = require('express');
const sheetsService = require('../services/sheetsService');

const router = express.Router();

// GET /api/stats -> aggregated dashboard/monitor numbers computed from real data
router.get('/', async (req, res, next) => {
  try {
    if (!sheetsService.isConfigured()) {
      return res.json({
        success: true,
        data: emptyStats(),
        warning: 'Google Sheets is not configured yet. No scan data available.'
      });
    }

    const records = await sheetsService.getAllScanRecords();

    if (!records.length) {
      return res.json({ success: true, data: emptyStats() });
    }

    const total = records.length;
    const safe = records.filter((r) => r.status === 'SAFE').length;
    const suspicious = records.filter((r) => r.status === 'SUSPICIOUS').length;
    const malicious = records.filter((r) => r.status === 'MALICIOUS').length;
    const critical = records.filter((r) => r.status === 'MALICIOUS' && Number(r.threatScore) >= 85).length;

    const detectionRate = total > 0 ? Math.round(((suspicious + malicious) / total) * 100) : 0;

    // Threat type breakdown
    const typeCounts = {};
    records.forEach((r) => {
      const t = r.threatType || 'Unknown';
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });

    // Last 7 days activity (by date)
    const activityMap = {};
    records.forEach((r) => {
      const day = (r.timestamp || '').slice(0, 10);
      if (!day) return;
      activityMap[day] = (activityMap[day] || 0) + 1;
    });
    const activityTrend = Object.entries(activityMap)
      .sort((a, b) => new Date(a[0]) - new Date(b[0]))
      .slice(-7)
      .map(([date, count]) => ({ date, count }));

    const recent = [...records]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 10);

    res.json({
      success: true,
      data: {
        totalScans: total,
        safeScans: safe,
        suspiciousScans: suspicious,
        maliciousScans: malicious,
        criticalThreats: critical,
        detectionRate,
        threatTypeBreakdown: typeCounts,
        activityTrend,
        recentScans: recent
      }
    });
  } catch (err) {
    next(err);
  }
});

function emptyStats() {
  return {
    totalScans: 0,
    safeScans: 0,
    suspiciousScans: 0,
    maliciousScans: 0,
    criticalThreats: 0,
    detectionRate: 0,
    threatTypeBreakdown: {},
    activityTrend: [],
    recentScans: []
  };
}

module.exports = router;
