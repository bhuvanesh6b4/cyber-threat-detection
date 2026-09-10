/**
 * monitor.js — live-ish monitoring dashboard driven entirely by
 * GET /api/stats. Polls every 20s. Uses Chart.js (loaded via CDN in
 * monitor.html) for the two charts.
 */
document.addEventListener('DOMContentLoaded', () => {
  const grid = document.getElementById('monitor-stat-grid');
  if (!grid) return; // not on monitor page

  let trendChart, typeChart;

  function esc(v) { return CTD.escapeHtml(v); }

  function renderEmptyState() {
    const tbody = document.getElementById('activity-body');
    if (tbody) tbody.innerHTML = `<tr class="empty-row"><td colspan="4">No scan data available.</td></tr>`;
  }

  function buildCharts(trend, typeBreakdown) {
    const trendCanvas = document.getElementById('trend-chart');
    const typeCanvas = document.getElementById('type-chart');
    if (!window.Chart || !trendCanvas || !typeCanvas) return;

    const trendLabels = trend.map((t) => t.date.slice(5));
    const trendData = trend.map((t) => t.count);

    if (trendChart) trendChart.destroy();
    trendChart = new Chart(trendCanvas, {
      type: 'line',
      data: {
        labels: trendLabels,
        datasets: [{
          label: 'Scans',
          data: trendData,
          borderColor: '#00dbe7',
          backgroundColor: 'rgba(0,219,231,0.15)',
          fill: true,
          tension: 0.35
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#b9cacb' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { ticks: { color: '#b9cacb' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
        }
      }
    });

    const typeLabels = Object.keys(typeBreakdown);
    const typeData = Object.values(typeBreakdown);

    if (typeChart) typeChart.destroy();
    typeChart = new Chart(typeCanvas, {
      type: 'doughnut',
      data: {
        labels: typeLabels.length ? typeLabels : ['No data'],
        datasets: [{
          data: typeData.length ? typeData : [1],
          backgroundColor: ['#ffb4ab', '#e8c423', '#00dbe7', '#bbc3ff', '#93000a', '#00c853']
        }]
      },
      options: {
        plugins: { legend: { position: 'bottom', labels: { color: '#b9cacb', boxWidth: 12 } } }
      }
    });
  }

  async function loadMonitor() {
    try {
      const res = await CTD.apiFetch('/stats');
      const s = res.data;

      document.getElementById('m-total').textContent = s.totalScans.toLocaleString();
      document.getElementById('m-safe').textContent = s.safeScans.toLocaleString();
      document.getElementById('m-suspicious').textContent = s.suspiciousScans.toLocaleString();
      document.getElementById('m-malicious').textContent = s.maliciousScans.toLocaleString();
      document.getElementById('m-critical').textContent = s.criticalThreats.toLocaleString();

      buildCharts(s.activityTrend, s.threatTypeBreakdown);

      const tbody = document.getElementById('activity-body');
      if (!s.recentScans.length) {
        renderEmptyState();
      } else {
        tbody.innerHTML = s.recentScans.map((r) => `
          <tr>
            <td>${CTD.timeAgo(r.timestamp)}</td>
            <td>${esc(r.inputType)}</td>
            <td><span class="badge ${CTD.statusBadgeClass(r.status)}"><span class="badge-dot"></span>${esc(r.status)}</span></td>
            <td>${esc(r.threatScore)}%</td>
          </tr>
        `).join('');
      }

      if (res.warning) CTD.toast(res.warning, 'info');
    } catch (err) {
      CTD.toast(err.message, 'error');
      renderEmptyState();
    }
  }

  loadMonitor();
  setInterval(loadMonitor, 20000);
});
