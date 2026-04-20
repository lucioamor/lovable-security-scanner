// ============================================================
// Sidepanel — Full Dashboard (Chrome Extension)
// ============================================================

import { t, setLocale, getLocale, loadLocale, LOCALE_FLAGS } from './lib/i18n.js';
import { getSeverityColor, isPreCutoff, getSeverity, computeRiskScore } from './lib/risk-scorer.js';

let currentPage = 'dashboard';
let results = [];
let summary = null;
let isDemoMode = false;
let selectedProject = null;
let detailOpen = false;
let hasSession = false;
let scanProgress = null;

// ---- Init ----
(async () => {
  await loadLocale();
  // Check session
  chrome.runtime.sendMessage({ type: 'CHECK_SESSION' }, (res) => {
    hasSession = res?.hasSession || false;
    // Load existing results
    chrome.runtime.sendMessage({ type: 'GET_RESULTS' }, (data) => {
      results = data?.results || [];
      summary = data?.summary || null;
      isDemoMode = data?.isDemoMode || false;
      render();
    });
  });

  // Listen for scan updates
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'SCAN_PROGRESS') { scanProgress = msg.progress; updateProgress(); }
    if (msg.type === 'SCAN_RESULT') { results.push(msg.result); }
    if (msg.type === 'SCAN_COMPLETE') {
      summary = msg.summary; scanProgress = null; render();
    }
    if (msg.type === 'SCAN_ERROR') { scanProgress = null; render(); }
  });
})();

// ---- Helpers ----
function navigate(page) { currentPage = page; render(); }
function fmtDate(iso) {
  try { return new Date(iso).toLocaleDateString(getLocale() === 'pt' ? 'pt-BR' : getLocale() === 'es' ? 'es-ES' : 'en-US', { day: '2-digit', month: 'short', year: 'numeric' }); } catch { return iso; }
}
function fmtDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}
function sevEmoji(s) { return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', clean: '🟢' }[s] || ''; }
function sevLabel(s) { return t(`severity.${s}`); }

function scoreRing(score, sev) {
  const r = 20, c = 2 * Math.PI * r, o = c - (score / 100) * c, clr = getSeverityColor(sev);
  return `<div class="risk-score-ring"><svg width="48" height="48" viewBox="0 0 48 48"><circle class="ring-bg" cx="24" cy="24" r="${r}" fill="none" stroke-width="3.5"/><circle class="ring-fill" cx="24" cy="24" r="${r}" fill="none" stroke="${clr}" stroke-width="3.5" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${o}"/></svg><span class="risk-score-value" style="color:${clr};font-size:0.75rem">${score}</span></div>`;
}

// ---- Render ----
function render() {
  // Top nav
  const tabs = [
    { id: 'dashboard', icon: '📊', label: t('nav.dashboard') },
    { id: 'results', icon: '📋', label: t('nav.results') },
    { id: 'scan', icon: '🔍', label: t('nav.run_scan') },
    { id: 'config', icon: '⚙️', label: t('nav.config') },
  ];
  document.getElementById('topnav').innerHTML = tabs.map(tb =>
    `<div class="nav-tab ${currentPage === tb.id ? 'active' : ''}" data-nav="${tb.id}">${tb.icon} ${tb.label}</div>`
  ).join('');

  // Language switcher
  document.getElementById('lang-switcher').innerHTML =
    ['en', 'pt', 'es'].map(l =>
      `<button class="lang-btn ${getLocale() === l ? 'active' : ''}" data-lang="${l}" style="border:1px solid ${getLocale() === l ? 'var(--accent-primary)' : 'var(--border-subtle)'};background:${getLocale() === l ? 'rgba(108,99,255,0.15)' : 'transparent'};border-radius:4px;cursor:pointer;padding:2px 6px;font-size:0.85rem">${LOCALE_FLAGS[l]}</button>`
    ).join('');

  // Credits label
  document.getElementById('credits-label').textContent = t('credits.title');

  // Page content
  let html = '';
  switch (currentPage) {
    case 'dashboard': html = renderDashboard(); break;
    case 'results': html = renderResults(); break;
    case 'scan': html = renderScan(); break;
    case 'config': html = renderConfig(); break;
  }
  document.getElementById('page-content').innerHTML = html + (detailOpen ? renderDetail() : '');
  attachEvents();
}

// ---- Dashboard ----
function renderDashboard() {
  if (!results.length) {
    return `<div class="page-header"><h1 class="page-title" style="font-size:1.2rem">${t('dashboard.title')}</h1><p class="page-subtitle">${t('dashboard.subtitle')}</p></div>
    <div class="empty-state"><div class="empty-state-icon">🔐</div><div class="empty-state-title">${t('dashboard.empty.title')}</div><div class="empty-state-desc">${t('dashboard.empty.desc')}</div>
    <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap"><button class="btn btn-primary" data-action="go-scan">🔍 ${t('dashboard.btn.start_scan')}</button><button class="btn btn-ghost" data-action="load-demo">📦 ${t('dashboard.btn.demo')}</button></div></div>`;
  }
  const cc = results.filter(r => r.severity === 'critical').length;
  const hc = results.filter(r => r.severity === 'high').length;
  const mc = results.filter(r => r.severity === 'medium').length;
  const cl = results.filter(r => r.severity === 'clean').length;
  const tf = results.reduce((s, r) => s + r.findings.length, 0);
  const pre = results.filter(r => isPreCutoff(r.createdAt)).length;

  return `<div class="page-header"><h1 class="page-title" style="font-size:1.2rem">${t('dashboard.title')}</h1><p class="page-subtitle">${results.length} ${t('dashboard.projects_scanned')} ${isDemoMode ? `— <span style="color:var(--color-medium)">${t('dashboard.demo_mode')}</span>` : ''}</p></div>
  <div class="stats-grid" style="grid-template-columns:repeat(5,1fr);gap:6px"><div class="card stat-card critical"><div class="stat-value">${cc}</div><div class="stat-label">${t('dashboard.stat.critical')}</div></div><div class="card stat-card high"><div class="stat-value">${hc}</div><div class="stat-label">${t('dashboard.stat.high')}</div></div><div class="card stat-card medium"><div class="stat-value">${mc}</div><div class="stat-label">${t('dashboard.stat.medium')}</div></div><div class="card stat-card clean"><div class="stat-value">${cl}</div><div class="stat-label">${t('dashboard.stat.clean')}</div></div><div class="card stat-card accent"><div class="stat-value">${tf}</div><div class="stat-label">${t('dashboard.stat.total_findings')}</div></div></div>
  ${pre > 0 ? `<div class="alert alert-danger" style="margin-top:12px"><span class="alert-icon">⚠️</span><div><strong>${pre} ${t('dashboard.alert.pre_cutoff_1')}</strong> ${t('dashboard.alert.pre_cutoff_2')}</div></div>` : ''}
  <div style="margin-top:16px"><h2 style="font-size:0.95rem;font-weight:700;margin-bottom:8px">${t('dashboard.projects_by_risk')}</h2>${projectList(results.sort((a, b) => b.riskScore - a.riskScore).slice(0, 5))}</div>
  <div class="export-actions" style="margin-top:16px"><button class="btn btn-ghost btn-sm" data-action="export-json">${t('dashboard.btn.export_json')}</button><button class="btn btn-ghost btn-sm" data-action="export-csv">${t('dashboard.btn.export_csv')}</button><button class="btn btn-ghost btn-sm" data-action="clear-results">${t('dashboard.btn.clear')}</button></div>`;
}

// ---- Results ----
function renderResults() {
  const sorted = [...results].sort((a, b) => b.riskScore - a.riskScore);
  return `<div class="page-header"><h1 class="page-title" style="font-size:1.2rem">${t('results.title')}</h1><p class="page-subtitle">${results.length} ${t('results.subtitle_1')}</p></div>
  ${results.length ? `<div style="display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap"><button class="btn btn-primary btn-sm" data-filter="all">${t('results.filter.all')} (${results.length})</button><button class="btn btn-ghost btn-sm" data-filter="critical">${t('results.filter.critical')} (${results.filter(r => r.severity === 'critical').length})</button><button class="btn btn-ghost btn-sm" data-filter="high">${t('results.filter.high')} (${results.filter(r => r.severity === 'high').length})</button><button class="btn btn-ghost btn-sm" data-filter="medium">${t('results.filter.medium')} (${results.filter(r => r.severity === 'medium').length})</button><button class="btn btn-ghost btn-sm" data-filter="clean">${t('results.filter.clean')} (${results.filter(r => r.severity === 'clean').length})</button></div>` : ''}
  ${projectList(sorted)}`;
}

// ---- Scan ----
function renderScan() {
  const isRunning = scanProgress?.status === 'running';
  let progress = '';
  if (scanProgress) {
    const p = scanProgress;
    progress = `<div class="progress-container" style="margin-top:12px"><div class="progress-header"><span class="progress-title">${p.status === 'running' ? `<span class="progress-spinner"></span> ${t('scan.progress.scanning')}` : t('scan.progress.completed')}</span><span class="progress-value">${p.percentage}%</span></div><div class="progress-bar"><div class="progress-fill" style="width:${p.percentage}%"></div></div><div class="progress-status">${p.currentProject ? `${t('scan.progress.current')} <strong>${p.currentProject}</strong>` : ''} — ${p.currentProjectIndex}/${p.totalProjects} ${t('scan.progress.projects')} — ${p.findings} ${t('scan.progress.findings')}</div></div>`;
  }
  return `<div class="page-header"><h1 class="page-title" style="font-size:1.2rem">${t('scan.title')}</h1><p class="page-subtitle">${t('scan.subtitle')}</p></div>
  <div class="status ${hasSession ? 'ok' : 'warn'}" style="padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:0.8rem;background:${hasSession ? 'rgba(46,213,115,0.1)' : 'rgba(255,211,42,0.1)'};border:1px solid ${hasSession ? 'rgba(46,213,115,0.3)' : 'rgba(255,211,42,0.3)'};color:${hasSession ? '#2ed573' : '#ffd32a'}">${hasSession ? t('scan.auth.ok') : t('scan.auth.missing')}</div>
  <div style="display:flex;gap:8px;margin-bottom:12px">${!isRunning ? `<button class="btn btn-primary" data-action="start-scan" ${!hasSession ? 'disabled' : ''}>${t('scan.btn.start')}</button><button class="btn btn-ghost" data-action="load-demo">${t('scan.btn.demo')}</button>` : `<button class="btn btn-danger" data-action="stop-scan">${t('scan.btn.stop')}</button>`}</div>
  ${progress}`;
}

// ---- Config ----
function renderConfig() {
  return `<div class="page-header"><h1 class="page-title" style="font-size:1.2rem">${t('config.title')}</h1><p class="page-subtitle">${t('config.subtitle')}</p></div>
  <div class="card" style="padding:16px;margin-bottom:12px"><div style="font-weight:700;margin-bottom:8px">${t('config.options.title')}</div><div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:12px">${t('config.options.desc')}</div>
  <div class="toggle-group"><label class="toggle"><input type="checkbox" id="t-files" checked><span class="toggle-slider"></span></label><label class="toggle-label" for="t-files">${t('config.toggle.files')}</label></div>
  <div class="toggle-group"><label class="toggle"><input type="checkbox" id="t-chat" checked><span class="toggle-slider"></span></label><label class="toggle-label" for="t-chat">${t('config.toggle.chat')}</label></div>
  <div class="toggle-group"><label class="toggle"><input type="checkbox" id="t-rls" checked><span class="toggle-slider"></span></label><label class="toggle-label" for="t-rls">${t('config.toggle.rls')}</label></div>
  <div class="input-group" style="margin-top:12px"><label class="input-label" for="i-delay">${t('config.delay.label')}</label><input class="input" type="number" id="i-delay" value="500" min="200" max="5000" step="100" style="max-width:150px"><div class="input-hint">${t('config.delay.hint')}</div></div></div>
  <button class="btn btn-primary" data-action="save-config">${t('config.btn.save')}</button>`;
}

// ---- Project List ----
function projectList(projects) {
  if (!projects.length) return `<div class="empty-state"><div class="empty-state-icon">📭</div><div class="empty-state-title">${t('empty.no_projects')}</div></div>`;
  return `<div class="project-list">${projects.map(p => {
    const fc = p.findings.length;
    return `<div class="card project-card severity-${p.severity}" data-pid="${p.projectId}" style="cursor:pointer">
    <div class="project-card-header"><div style="display:flex;align-items:center;gap:10px">${scoreRing(p.riskScore, p.severity)}<div><div class="project-name">${sevEmoji(p.severity)} ${p.projectName}</div><div class="project-meta"><span class="project-meta-item">📅 ${fmtDate(p.createdAt)}</span><span class="project-meta-item">📁 ${p.filesScanned} ${t('project.files')}</span></div></div></div><span class="severity-badge ${p.severity}">${sevLabel(p.severity)}</span></div>
    <div class="project-findings-row">
      <span class="finding-tag ${p.bolaFileStatus === 'vulnerable' ? 'critical' : ''}"><span class="status-dot ${p.bolaFileStatus}"></span>${t('project.files_label')} ${p.bolaFileStatus === 'vulnerable' ? t('project.exposed') : t('project.protected')}</span>
      <span class="finding-tag ${p.bolaChatStatus === 'vulnerable' ? 'critical' : ''}"><span class="status-dot ${p.bolaChatStatus}"></span>${t('project.chat_label')} ${p.bolaChatStatus === 'vulnerable' ? t('project.exposed') : t('project.protected')}</span>
      ${fc > 0 ? `<span class="finding-tag ${p.findings.some(f => f.severity === 'critical') ? 'critical' : 'high'}">${fc} ${t('project.findings')}</span>` : ''}
    </div></div>`;
  }).join('')}</div>`;
}

// ---- Detail Panel ----
function renderDetail() {
  if (!selectedProject) return '';
  const p = selectedProject;
  const clr = getSeverityColor(p.severity);
  return `<div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100" data-action="close-detail"></div>
  <div style="position:fixed;right:0;top:0;bottom:0;width:100%;max-width:400px;background:var(--bg-page);z-index:101;overflow-y:auto;border-left:1px solid var(--border-subtle);padding:20px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div><div style="font-weight:700">${sevEmoji(p.severity)} ${p.projectName}</div><div style="font-size:0.75rem;color:var(--text-secondary)">Score: <span style="color:${clr};font-weight:800">${p.riskScore}/100</span></div></div>
      <button style="background:none;border:none;color:var(--text-secondary);cursor:pointer;font-size:1.2rem" data-action="close-detail">✕</button>
    </div>
    <div style="margin-bottom:16px"><div class="detail-section-title">${t('detail.info.title')}</div>
    <div class="kv-grid"><span class="kv-key">${t('detail.info.created')}</span><span class="kv-value">${fmtDate(p.createdAt)} ${isPreCutoff(p.createdAt) ? t('detail.info.pre_patch') : t('detail.info.post_patch')}</span>
    <span class="kv-key">${t('detail.exposure.files_bola')}</span><span class="kv-value">${p.bolaFileStatus === 'vulnerable' ? t('detail.exposure.exposed') : t('detail.exposure.protected')}</span>
    <span class="kv-key">${t('detail.exposure.chat_bola')}</span><span class="kv-value">${p.bolaChatStatus === 'vulnerable' ? t('detail.exposure.exposed') : t('detail.exposure.protected')}</span></div></div>
    <div><div class="detail-section-title">${t('detail.findings.title')} (${p.findings.length})</div>
    ${p.findings.length === 0 ? `<div style="text-align:center;padding:16px;color:var(--text-muted)">${t('detail.findings.clean')}</div>` : p.findings.map(f => `<div class="finding-card ${f.severity}"><div class="finding-title"><span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span> ${f.title}</div><div class="finding-description">${f.description}</div><div class="finding-evidence">${f.evidence}</div><div class="finding-recommendation">💡 ${f.recommendation}</div></div>`).join('')}
    </div>
  </div>`;
}

// ---- Progress update (in-place) ----
function updateProgress() {
  const c = document.querySelector('.progress-container');
  if (c && scanProgress) {
    const fill = c.querySelector('.progress-fill');
    const val = c.querySelector('.progress-value');
    const st = c.querySelector('.progress-status');
    if (fill) fill.style.width = `${scanProgress.percentage}%`;
    if (val) val.textContent = `${scanProgress.percentage}%`;
    if (st) st.innerHTML = `${scanProgress.currentProject ? `${t('scan.progress.current')} <strong>${scanProgress.currentProject}</strong>` : ''} — ${scanProgress.currentProjectIndex}/${scanProgress.totalProjects} ${t('scan.progress.projects')} — ${scanProgress.findings} ${t('scan.progress.findings')}`;
  } else { render(); }
}

// ---- Events ----
function attachEvents() {
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', () => navigate(el.dataset.nav));
  });
  document.querySelectorAll('[data-lang]').forEach(el => {
    el.addEventListener('click', () => { setLocale(el.dataset.lang); render(); });
  });
  document.querySelectorAll('[data-pid]').forEach(el => {
    el.addEventListener('click', () => {
      selectedProject = results.find(r => r.projectId === el.dataset.pid);
      if (selectedProject) { detailOpen = true; render(); }
    });
  });
  document.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', () => {
      switch (el.dataset.action) {
        case 'go-scan': navigate('scan'); break;
        case 'load-demo':
          chrome.runtime.sendMessage({ type: 'LOAD_DEMO' }, (res) => {
            if (res) { results = res.results; summary = res.summary; isDemoMode = true; navigate('dashboard'); }
          }); break;
        case 'start-scan':
          results = []; isDemoMode = false;
          chrome.runtime.sendMessage({ type: 'START_SCAN', config: { includeFiles: true, includeChat: true, testRLS: true, scanDelay: parseInt(document.getElementById('i-delay')?.value || '500') } });
          scanProgress = { status: 'running', totalProjects: 0, currentProjectIndex: 0, currentProject: '', findings: 0, percentage: 0, errors: [] };
          render(); break;
        case 'stop-scan':
          chrome.runtime.sendMessage({ type: 'STOP_SCAN' }); break;
        case 'close-detail': detailOpen = false; selectedProject = null; render(); break;
        case 'export-json': exportJSON(); break;
        case 'export-csv': exportCSV(); break;
        case 'clear-results':
          chrome.runtime.sendMessage({ type: 'CLEAR_RESULTS' });
          results = []; summary = null; isDemoMode = false; render(); break;
        case 'save-config':
          const btn = el; const orig = btn.innerHTML; btn.innerHTML = t('config.btn.saved');
          setTimeout(() => { btn.innerHTML = orig; }, 1500); break;
      }
    });
  });
  document.querySelectorAll('[data-filter]').forEach(el => {
    el.addEventListener('click', () => {
      const f = el.dataset.filter;
      document.querySelectorAll('.project-card').forEach(c => {
        c.style.display = f === 'all' || c.classList.contains(`severity-${f}`) ? '' : 'none';
      });
      document.querySelectorAll('[data-filter]').forEach(b => {
        b.className = b.dataset.filter === f ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm';
      });
    });
  });
}

// ---- Export ----
function exportJSON() {
  const blob = new Blob([JSON.stringify({ scanDate: new Date().toISOString(), summary, results }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  chrome.downloads?.download?.({ url, filename: `lovable-scan-${new Date().toISOString().slice(0, 10)}.json` });
}
function exportCSV() {
  const h = ['Project', 'ID', 'Created', 'Score', 'Severity', 'Findings', 'BOLA Files', 'BOLA Chat'];
  const rows = results.map(r => [r.projectName, r.projectId, r.createdAt, r.riskScore, r.severity, r.findings.length, r.bolaFileStatus, r.bolaChatStatus].map(c => `"${c}"`).join(','));
  const blob = new Blob([[h.join(','), ...rows].join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  chrome.downloads?.download?.({ url, filename: `lovable-scan-${new Date().toISOString().slice(0, 10)}.csv` });
}
