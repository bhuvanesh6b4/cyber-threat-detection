/**
 * Cyber Threat Detection System - Backend Server
 * Express REST API. Talks to Google Sheets (via Apps Script Web App)
 * as the storage layer, and to optional external security APIs.
 */
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const scanRoutes = require('./routes/scan');
const reportsRoutes = require('./routes/reports');
const statsRoutes = require('./routes/stats');

const app = express();
const PORT = process.env.PORT || 5000;

// ---------- Security middleware ----------
app.use(helmet());

// FRONTEND_URL supports one or more comma-separated origins, e.g.:
//   FRONTEND_URL=http://127.0.0.1:5500,https://yourname.github.io
// This lets you test local dev and a deployed GitHub Pages frontend
// against the same backend without juggling two configs.
const allowedOrigins = (process.env.FRONTEND_URL || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // No Origin header (curl, server-to-server, some mobile webviews) — allow.
    if (!origin) return callback(null, true);
    // No FRONTEND_URL configured at all — allow everything (local/demo convenience).
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.warn(`[CORS] Blocked request from unlisted origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// Global rate limiter - protects the free Apps Script quota too
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests. Please try again in a few minutes.'
  }
});
app.use('/api/', limiter);

// ---------- Routes ----------
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    data: {
      status: 'online',
      timestamp: new Date().toISOString(),
      sheetsConfigured: Boolean(process.env.GOOGLE_APPS_SCRIPT_URL),
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      virusTotalConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY),
      version: '1.2.0'
    }
  });
});

app.use('/api/scan', scanRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/stats', statsRoutes);

// ---------- 404 handler ----------
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// ---------- Global error handler ----------
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.message);
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  });
});

app.listen(PORT, () => {
  console.log(`Cyber Threat Detection backend running on http://localhost:${PORT}`);
  console.log(`Google Sheets configured: ${Boolean(process.env.GOOGLE_APPS_SCRIPT_URL)}`);
});
