/**
 * reports.js — searchable/filterable reports table backed by GET /api/reports.
 */
document.addEventListener('DOMContentLoaded', () => {
  const tbody = document.getElementById('reports-body');
  if (!tbody) return; // not on reports page

  const searchInput = document.getElementById('reports-search');
  const statusFilter = document.getElementById('reports-status-filter');
  const pageInfo = document.getElementById('reports-page-info');
  const prevBtn = document.getElementById('reports-prev');
  const nextBtn = document.getElementById('reports-next');

  const PAGE_SIZE = 10;
  let allRecords = [];
  let filtered = [];
  let currentPage = 1;

  function esc(v) { return CTD.escapeHtml(v); }

  function applyFilters() {
    const q = (searchInput.value || '').toLowerCase();
    const status = statusFilter.value;

    filtered = allRecords.filter((r) => {
      const matchesStatus = status === 'ALL' || (r.status || '').toUpperCase() === status;
      const matchesSearch = !q || JSON.stringify(r).toLowerCase().includes(q);
      return matchesStatus && matchesSearch;
    });
    currentPage = 1;
    render();
  }

  function render() {
    const start = (currentPage - 1) * PAGE_SIZE;
    const pageItems = filtered.slice(start, start + PAGE_SIZE);
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

    if (!pageItems.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="9">No scan data available.</td></tr>`;
    } else {
      tbody.innerHTML = pageItems.map((r) => `
        <tr>
          <td class="strong">${esc(r.scanId)}</td>
          <td>${esc(new Date(r.timestamp).toLocaleString())}</td>
          <td>${esc(r.inputType)}</td>
          <td>${esc((r.input || '').toString().slice(0, 40))}</td>
          <td><span class="badge ${CTD.statusBadgeClass(r.status)}"><span class="badge-dot"></span>${esc(r.status)}</span></td>
          <td>${esc(r.threatScore)}%</td>
          <td>${esc(r.threatType)}</td>
          <td>${esc(r.confidence)}%</td>
          <td>${esc(r.detectionSource)}</td>
        </tr>
      `).join('');
    }

    pageInfo.textContent = `Page ${currentPage} of ${totalPages} (${filtered.length} records)`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
  }

  prevBtn.addEventListener('click', () => { if (currentPage > 1) { currentPage--; render(); } });
  nextBtn.addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (currentPage < totalPages) { currentPage++; render(); }
  });
  searchInput.addEventListener('input', applyFilters);
  statusFilter.addEventListener('change', applyFilters);

  async function loadReports() {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="9"><span class="loading-text"><span class="spinner"></span>Loading reports...</span></td></tr>`;
    try {
      const res = await CTD.apiFetch('/reports');
      allRecords = res.data || [];
      applyFilters();
      if (res.warning) CTD.toast(res.warning, 'info');
    } catch (err) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="9">${esc(err.message)}</td></tr>`;
      CTD.toast(err.message, 'error');
    }
  }

  loadReports();
});
