/**
 * scanner.js — wires the Scanner page tabs to real backend calls.
 * Depends on app.js (CTD global) being loaded first.
 */
document.addEventListener('DOMContentLoaded', () => {
  const tabButtons = document.querySelectorAll('.tab-btn[data-tab]');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabButtons.forEach((b) => b.classList.remove('active'));
      tabPanels.forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`panel-${btn.dataset.tab}`).classList.add('active');
      clearResults();
    });
  });

  const resultsContainer = document.getElementById('results-container');

  function clearResults() {
    resultsContainer.innerHTML = `
      <div class="results-empty">
        <div style="font-size:32px;">🛡</div>
        <p>Run a scan to see results here.</p>
      </div>`;
  }

  function renderLoading(message) {
    resultsContainer.innerHTML = `
      <div class="results-empty">
        <div class="loading-text"><span class="spinner"></span>${message}</div>
      </div>`;
  }

  function statusEmoji(status) {
    if (status === 'SAFE') return '🟢';
    if (status === 'SUSPICIOUS') return '🟡';
    return '🔴';
  }

  function renderResult(data) {
    const esc = CTD.escapeHtml;
    const isDemo = /demo/i.test(data.source || '');
    resultsContainer.innerHTML = `
      <div class="result-status-row">
        <div class="card-title">${statusEmoji(data.status)} ${esc(data.status)}</div>
        <span class="badge ${CTD.statusBadgeClass(data.status)}"><span class="badge-dot"></span>${esc(data.status)}</span>
      </div>

      ${isDemo ? `<div class="demo-flag">⚠ ${esc(data.source)} — for demonstration purposes only, not a verified real-world threat verdict.</div>` : ''}

      <div class="score-grid">
        <div class="score-box">
          <div class="score-label">THREAT SCORE</div>
          <div class="score-value ${data.threatScore >= 50 ? 'red' : 'cyan'}">${esc(data.threatScore)}%</div>
        </div>
        <div class="score-box">
          <div class="score-label">CONFIDENCE</div>
          <div class="score-value cyan">${esc(data.confidence)}%</div>
        </div>
      </div>

      <div class="explain-box">
        <div class="explain-source">Detection Source: ${esc(data.source)}</div>
        <div><strong style="color:var(--text-heading)">Threat Type:</strong> ${esc(data.threatType)}</div>
        <div class="evidence-list">
          ${(data.reasons || []).map((r) => `<div class="evidence-item">• ${esc(r)}</div>`).join('')}
        </div>
      </div>

      <div class="explain-box">
        <strong style="color:var(--text-heading)">Recommendation</strong>
        <div>${esc(data.recommendation)}</div>
      </div>

      <div class="result-meta">
        Scan completed at: ${esc(new Date(data.scannedAt).toLocaleString())}<br>
        Scan ID: ${esc(data.scanId)} ${data.saved ? '— saved to Google Sheets' : '— ⚠ NOT saved (' + esc(data.saveError || 'Sheets not configured') + ')'}
      </div>
    `;
  }

  function renderError(message) {
    resultsContainer.innerHTML = `
      <div class="results-empty">
        <div style="font-size:32px;">⚠</div>
        <p style="color:var(--accent-red)">${CTD.escapeHtml(message)}</p>
      </div>`;
    CTD.toast(message, 'error');
  }

  function setButtonLoading(btn, loading, label) {
    btn.disabled = loading;
    btn.innerHTML = loading ? `<span class="spinner"></span> ${label}` : btn.dataset.originalLabel;
  }

  // ---------------- URL Scanner ----------------
  const urlForm = document.getElementById('url-scan-form');
  if (urlForm) {
    const btn = urlForm.querySelector('button[type="submit"]');
    btn.dataset.originalLabel = btn.innerHTML;
    urlForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('url-input').value.trim();
      if (!url) return renderError('Please enter a URL.');

      renderLoading('Analyzing URL...');
      setButtonLoading(btn, true, 'Scanning...');
      try {
        const res = await CTD.apiFetch('/scan/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        renderResult(res.data);
      } catch (err) {
        renderError(err.message);
      } finally {
        setButtonLoading(btn, false);
      }
    });
  }

  // ---------------- Text Scanner ----------------
  const textForm = document.getElementById('text-scan-form');
  if (textForm) {
    const btn = textForm.querySelector('button[type="submit"]');
    btn.dataset.originalLabel = btn.innerHTML;
    textForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = document.getElementById('text-input').value.trim();
      if (!text) return renderError('Please enter some text.');

      renderLoading('Analyzing text for phishing patterns...');
      setButtonLoading(btn, true, 'Scanning...');
      try {
        const res = await CTD.apiFetch('/scan/text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        });
        renderResult(res.data);
      } catch (err) {
        renderError(err.message);
      } finally {
        setButtonLoading(btn, false);
      }
    });
  }

  // ---------------- Email Scanner ----------------
  const emailForm = document.getElementById('email-scan-form');
  if (emailForm) {
    const btn = emailForm.querySelector('button[type="submit"]');
    btn.dataset.originalLabel = btn.innerHTML;
    emailForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const sender = document.getElementById('email-sender').value.trim();
      const subject = document.getElementById('email-subject').value.trim();
      const body = document.getElementById('email-body').value.trim();
      if (!sender || !subject || !body) return renderError('Sender, subject, and body are all required.');

      renderLoading('Analyzing email for spoofing and phishing indicators...');
      setButtonLoading(btn, true, 'Scanning...');
      try {
        const res = await CTD.apiFetch('/scan/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sender, subject, body })
        });
        renderResult(res.data);
      } catch (err) {
        renderError(err.message);
      } finally {
        setButtonLoading(btn, false);
      }
    });
  }

  // ---------------- File Scanner ----------------
  const fileForm = document.getElementById('file-scan-form');
  const dropzone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('file-input');
  const fileNameLabel = document.getElementById('file-name-label');

  const fileInfo = document.getElementById('file-info');
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.zip', '.csv', '.log'];

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function showFile(file) {
    if (!file) return;
    const lower = file.name.toLowerCase();
    const allowed = ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
    if (!allowed) {
      fileInput.value = '';
      fileNameLabel.textContent = 'Click or drag a file here';
      if (fileInfo) fileInfo.hidden = true;
      return renderError(`Unsupported file type. Allowed: ${ALLOWED_EXTENSIONS.join(' ')}`);
    }
    if (file.size > MAX_FILE_BYTES) {
      fileInput.value = '';
      fileNameLabel.textContent = 'Click or drag a file here';
      if (fileInfo) fileInfo.hidden = true;
      return renderError('File is larger than 5 MB. Please choose a smaller file.');
    }

    fileNameLabel.textContent = file.name;
    if (fileInfo) {
      fileInfo.hidden = false;
      fileInfo.innerHTML = `
        <div><strong>Selected file</strong></div>
        <div class="file-info-grid">
          <span>Name</span><b>${CTD.escapeHtml(file.name)}</b>
          <span>Size</span><b>${formatBytes(file.size)}</b>
          <span>Type</span><b>${CTD.escapeHtml(file.type || 'Unknown')}</b>
        </div>`;
    }
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
    });
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        showFile(e.dataTransfer.files[0]);
      }
    });
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) showFile(fileInput.files[0]);
    });
  }

  if (fileForm) {
    const btn = fileForm.querySelector('button[type="submit"]');
    btn.dataset.originalLabel = btn.innerHTML;
    fileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!fileInput.files.length) return renderError('Please choose a file first.');
      const selectedFile = fileInput.files[0];
      if (selectedFile.size > MAX_FILE_BYTES) return renderError('File is larger than 5 MB. Please choose a smaller file.');

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);

      renderLoading('Uploading and scanning file... (not stored, not executed)');
      setButtonLoading(btn, true, 'Scanning...');
      try {
        const res = await CTD.apiFetch('/scan/file', { method: 'POST', body: formData });
        renderResult(res.data);
      } catch (err) {
        renderError(err.message);
      } finally {
        setButtonLoading(btn, false);
      }
    });
  }

  clearResults();
});
