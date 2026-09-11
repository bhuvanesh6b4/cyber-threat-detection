/**
 * config.js
 * THE ONLY FILE YOU NEED TO EDIT to point the frontend at a different
 * backend. Loaded before app.js on every page.
 *
 * Local development (default): http://localhost:5000/api
 * Production (GitHub Pages, etc.): change API_BASE_URL below to your
 * deployed backend's URL, e.g. "https://your-app.onrender.com/api"
 */
(function () {
  const LOCAL_DEFAULT = 'http://localhost:5000/api';

  // ---- EDIT THIS LINE FOR PRODUCTION ----
  const API_BASE_URL = 'https://cyber-threat-detection-6u6x.onrender.com';
  // ----------------------------------------

  // Optional override for quick testing without editing this file:
  // append ?api=https://your-backend.example.com/api to any page URL.
  const params = new URLSearchParams(window.location.search);
  const override = params.get('api');

  window.CTD_API_BASE = override || API_BASE_URL;
})();
