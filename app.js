/**
 * app.js
 * Shared across all pages: API config, fetch helper, toast notifications,
 * backend health/status pill, nav active-state, and (on index.html) the
 * dashboard stats loader.
 *
 * IMPORTANT: change API_BASE to your deployed backend URL once you host it
 * (e.g. Render/Railway). For local development the default is correct.
 */
const CTD = (() => {
  const API_BASE = window.CTD_API_BASE || 'https://cyber-threat-detection-6u6x.onrender.com/';

  function toast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  }

  async function apiFetch(path, options = {}) {
    let response;
    try {
      response = await fetch(`${API_BASE}${path}`, options);
    } catch (err) {
      throw new Error('Backend server is unavailable. Please start the backend (cd backend && npm start).');
    }

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(`Backend returned an unexpected response (status ${response.status}).`);
    }

    if (!response.ok || !data.success) {
      throw new Error(data.error || `Request failed (status ${response.status}).`);
    }
    return data;
  }

  function setActiveNav() {
    const page = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-link[data-page]').forEach((link) => {
      link.classList.toggle('active', link.dataset.page === page);
    });
  }

  async function refreshStatusPill() {
    const pill = document.getElementById('status-pill');
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-label');
    if (!pill) return;

    try {
      const res = await apiFetch('/health');
      pill.classList.remove('offline');
      dot.classList.remove('offline');
      label.textContent = 'System Status: ONLINE';
      return res.data;
    } catch (err) {
      pill.classList.add('offline');
      dot.classList.add('offline');
      label.textContent = 'Backend Offline';
      return null;
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  }

  function statusBadgeClass(status) {
    switch ((status || '').toUpperCase()) {
      case 'MALICIOUS': return 'badge-critical';
      case 'SUSPICIOUS': return 'badge-high';
      case 'SAFE': return 'badge-low';
      default: return 'badge-low';
    }
  }

  function timeAgo(isoString) {
    if (!isoString) return '-';
    const diffMs = Date.now() - new Date(isoString).getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `-${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `-${hrs}h`;
    return `-${Math.floor(hrs / 24)}d`;
  }

  // ---------------- Dashboard (index.html) ----------------
  async function loadDashboard() {
    const grid = document.getElementById('stat-grid');
    if (!grid) return; // not on dashboard page

    try {
      const res = await apiFetch('/stats');
      const s = res.data;

      document.getElementById('stat-total').textContent = s.totalScans.toLocaleString();
      document.getElementById('stat-threats').textContent = (s.suspiciousScans + s.maliciousScans).toLocaleString();
      document.getElementById('stat-safe').textContent = s.safeScans.toLocaleString();
      document.getElementById('stat-suspicious').textContent = s.suspiciousScans.toLocaleString();
      document.getElementById('stat-critical').textContent = s.criticalThreats.toLocaleString();
      document.getElementById('stat-rate').textContent = `${s.detectionRate}%`;

      const tbody = document.getElementById('recent-scans-body');
      if (tbody) {
        if (!s.recentScans.length) {
          tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No scan data available.</td></tr>`;
        } else {
          tbody.innerHTML = s.recentScans.map((r) => `
            <tr>
              <td class="strong">${escapeHtml(r.input || '').slice(0, 40)}</td>
              <td>${escapeHtml(r.threatType)}</td>
              <td><span class="badge ${statusBadgeClass(r.status)}"><span class="badge-dot"></span>${escapeHtml(r.status)}</span></td>
              <td>${escapeHtml(r.threatScore)}%</td>
              <td>${timeAgo(r.timestamp)}</td>
            </tr>
          `).join('');
        }
      }

      if (res.warning) toast(res.warning, 'info');
    } catch (err) {
      toast(err.message, 'error');
      const tbody = document.getElementById('recent-scans-body');
      if (tbody) tbody.innerHTML = `<tr class="empty-row"><td colspan="5">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    setActiveNav();
    refreshStatusPill();
    loadDashboard();
    setInterval(refreshStatusPill, 30000);
  });

  return { API_BASE, apiFetch, toast, escapeHtml, statusBadgeClass, timeAgo, refreshStatusPill };
})();
