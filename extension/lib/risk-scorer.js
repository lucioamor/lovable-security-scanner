// ============================================================
// Risk Scorer
// ============================================================

const CUTOFF_EARLY = new Date('2025-05-25T00:00:00Z');
const CUTOFF_LATE = new Date('2025-11-01T00:00:00Z');

export function isPreCutoff(dateStr) {
  try { return new Date(dateStr) < CUTOFF_LATE; } catch { return false; }
}

export function computeRiskScore(result) {
  let score = 0;
  const created = new Date(result.createdAt);

  // Temporal risk
  if (created < CUTOFF_EARLY) score += 80;
  else if (created < CUTOFF_LATE) score += 60;

  // BOLA exposure
  if (result.bolaFileStatus === 'vulnerable') score += 60;
  if (result.bolaChatStatus === 'vulnerable') score += 60;

  // Content findings
  for (const f of result.findings) {
    if (f.severity === 'critical') score += 30;
    else if (f.severity === 'high') score += 20;
    else if (f.severity === 'medium') score += 10;
  }

  // RLS
  if (result.rlsStatus === 'missing') score += 40;

  // Activity recency bonus
  const daysSinceEdit = (Date.now() - new Date(result.updatedAt).getTime()) / 86400000;
  if (daysSinceEdit < 30) score += 10;

  return Math.min(100, score);
}

export function getSeverity(score) {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

export function getSeverityColor(sev) {
  const m = { critical: '#ff4757', high: '#ff8c42', medium: '#ffd32a', low: '#3498db', clean: '#2ed573' };
  return m[sev] || '#888';
}

export function getSeverityLabel(sev) {
  const { t } = await_i18n();
  return t ? t(`severity.${sev}`) : sev;
}

// Lazy import to avoid circular dependency — caller provides t()
let _t = null;
export function setTranslator(fn) { _t = fn; }
function await_i18n() { return { t: _t }; }
