// ============================================================
// Scanner Engine — Orchestrator (Chrome Extension)
// ============================================================

import { getSessionToken, listProjects, testBOLA, getProjectFiles, getFileContent, getProjectMessages, setDelay } from './api-client.js';
import { scanContent, isSensitiveFile, SENSITIVE_FILES } from './data-patterns.js';
import { computeRiskScore, getSeverity } from './health-scorer.js';

let aborted = false;

export function abortScan() { aborted = true; }

export async function runScan(config, onProgress, onResult) {
  aborted = false;
  setDelay(config.scanDelay || 500);

  const token = await getSessionToken();
  if (!token) throw new Error('No session token');

  const projects = await listProjects();
  const filtered = config.projectFilter?.length
    ? projects.filter(p => config.projectFilter.includes(p.id))
    : projects;

  const summary = {
    totalProjects: filtered.length, scannedProjects: 0,
    criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, cleanCount: 0,
    topFindings: [], scanStartTime: new Date().toISOString(), scanEndTime: '',
    totalDurationMs: 0,
  };

  const startTime = Date.now();
  const progress = {
    status: 'running', totalProjects: filtered.length,
    currentProjectIndex: 0, currentProject: '', findings: 0,
    percentage: 0, errors: [],
  };

  for (let i = 0; i < filtered.length; i++) {
    if (aborted) { progress.status = 'paused'; onProgress({ ...progress }); break; }

    const project = filtered[i];
    progress.currentProjectIndex = i + 1;
    progress.currentProject = project.name || project.id;
    progress.percentage = Math.round(((i + 1) / filtered.length) * 100);
    onProgress({ ...progress });

    try {
      const result = await scanProject(project, config);
      progress.findings += result.findings.length;
      onResult(result);
      summary.scannedProjects++;

      if (result.severity === 'critical') summary.criticalCount++;
      else if (result.severity === 'high') summary.highCount++;
      else if (result.severity === 'medium') summary.mediumCount++;
      else if (result.severity === 'low') summary.lowCount++;
      else summary.cleanCount++;
    } catch (e) {
      progress.errors.push(`${project.name || project.id}: ${e.message}`);
      onProgress({ ...progress });
    }
  }

  summary.scanEndTime = new Date().toISOString();
  summary.totalDurationMs = Date.now() - startTime;
  progress.status = aborted ? 'paused' : 'completed';
  onProgress({ ...progress });
  return summary;
}

async function scanProject(project, config) {
  const start = Date.now();
  const result = {
    projectId: project.id,
    projectName: project.name || project.id,
    createdAt: project.created_at || project.createdAt || new Date().toISOString(),
    updatedAt: project.updated_at || project.updatedAt || new Date().toISOString(),
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: 0,
    bolaFileStatus: 'unknown',
    bolaChatStatus: 'unknown',
    supabaseDetected: false,
    supabaseUrl: null,
    rlsStatus: 'not_tested',
    findings: [],
    filesScanned: 0,
    chatMessagesScanned: 0,
    riskScore: 0,
    severity: 'clean',
  };

  // BOLA test
  const bola = await testBOLA(project.id);
  result.bolaFileStatus = bola.fileStatus;
  result.bolaChatStatus = bola.chatStatus;

  // Deep scan for secrets if files accessible
  if (config.includeFiles && bola.fileStatus === 'vulnerable') {
    try {
      const files = await getProjectFiles(project.id);
      if (files && Array.isArray(files)) {
        const toScan = files.filter(f => isSensitiveFile(f.path || f.name || ''));
        for (const file of toScan.slice(0, 20)) {
          const content = await getFileContent(project.id, file.path || file.name);
          if (content) {
            const findings = scanContent(content, file.path || file.name);
            result.findings.push(...findings);
            // Detect Supabase
            const sbMatch = content.match(/https:\/\/([a-z]{20})\.supabase\.co/);
            if (sbMatch) {
              result.supabaseDetected = true;
              result.supabaseUrl = sbMatch[0];
            }
          }
          result.filesScanned++;
        }
      }
    } catch { /* continue */ }
  }

  // Chat scan
  if (config.includeChat && bola.chatStatus === 'vulnerable') {
    try {
      const messages = await getProjectMessages(project.id);
      if (messages && Array.isArray(messages)) {
        for (const msg of messages.slice(0, 100)) {
          const content = msg.content || msg.text || msg.body || '';
          if (content.length > 10) {
            const findings = scanContent(content, `chat:${msg.id || 'message'}`);
            result.findings.push(...findings);
          }
          result.chatMessagesScanned++;
        }
      }
    } catch { /* continue */ }
  }

  // Add BOLA findings
  if (result.bolaFileStatus === 'vulnerable') {
    result.findings.unshift({
      id: crypto.randomUUID(), ruleId: 'bola_files', severity: 'critical',
      title: 'Exposure: Source code accessible',
      vector: 'bola_files', source: 'api.lovable.dev',
      description: 'Endpoint returns 200 OK without ownership verification',
      evidence: `HTTP 200 — ${result.filesScanned} files`,
      recommendation: 'Contact Lovable support to apply retroactive ownership check on this project.',
    });
  }
  if (result.bolaChatStatus === 'vulnerable') {
    result.findings.unshift({
      id: crypto.randomUUID(), ruleId: 'bola_chat', severity: 'critical',
      title: 'Exposure: Chat history accessible',
      vector: 'bola_chat', source: 'api.lovable.dev',
      description: 'Chat history exposed',
      evidence: `HTTP 200 — ${result.chatMessagesScanned} messages`,
      recommendation: 'Contact Lovable support. Consider deleting sensitive chat history.',
    });
  }

  result.scanDurationMs = Date.now() - start;
  result.riskScore = computeRiskScore(result);
  result.severity = getSeverity(result.riskScore);
  return result;
}

// Demo mode
export function generateDemoData() {
  return [
    makeDemoProject('Admin Panel v2', '2025-06-15', '2026-04-10', 'vulnerable', 'vulnerable', true, 'missing', 23, 312, [
      { id: '1', ruleId: 'bola_files', severity: 'critical', title: 'Exposure: Source code accessible', vector: 'bola_files', source: 'api', description: 'Endpoint returns 200 OK without ownership', evidence: 'HTTP 200 — 47 files', recommendation: 'Contact Lovable support.' },
      { id: '2', ruleId: 'bola_chat', severity: 'critical', title: 'Exposure: Chat accessible', vector: 'bola_chat', source: 'api', description: 'Chat history exposed', evidence: 'HTTP 200 — 312 messages', recommendation: 'Delete sensitive chat history.' },
      { id: '3', ruleId: 'supabase_service_role', severity: 'critical', title: 'Supabase Service Role Key in client.ts', vector: 'hardcoded_secret', source: 'client.ts', description: 'Database admin key exposed', evidence: 'eyJh•••••Lz1', recommendation: 'Rotate key immediately.' },
      { id: '4', ruleId: 'rls_missing', severity: 'critical', title: 'RLS missing: users', vector: 'rls_missing', source: 'supabase', description: 'Table accessible without auth', evidence: 'users table returns data', recommendation: 'ALTER TABLE users ENABLE ROW LEVEL SECURITY;' },
      { id: '5', ruleId: 'openai_key', severity: 'critical', title: 'OpenAI API Key in utils.ts', vector: 'hardcoded_secret', source: 'utils.ts', description: 'AI service key exposed', evidence: 'sk-A•••••x7Q', recommendation: 'Rotate key in OpenAI dashboard.' },
    ]),
    makeDemoProject('E-commerce MVP', '2025-09-01', '2026-04-10', 'vulnerable', 'vulnerable', true, 'missing', 42, 520, [
      { id: '6', ruleId: 'bola_files', severity: 'critical', title: 'Exposure: Source code accessible', vector: 'bola_files', source: 'api', description: 'Endpoint returns 200', evidence: 'HTTP 200 — 89 files', recommendation: 'Contact Lovable support.' },
      { id: '7', ruleId: 'bola_chat', severity: 'critical', title: 'Exposure: Chat accessible', vector: 'bola_chat', source: 'api', description: 'Chat exposed', evidence: 'HTTP 200 — 520 messages', recommendation: 'Delete chat.' },
      { id: '8', ruleId: 'stripe_secret', severity: 'critical', title: 'Stripe Secret Key', vector: 'hardcoded_secret', source: 'checkout.ts', description: 'Payment key exposed', evidence: 'sk_live•••••', recommendation: 'Rotate in Stripe dashboard.' },
      { id: '9', ruleId: 'cpf', severity: 'high', title: 'CPF in seed data', vector: 'pii_in_code', source: 'seed.sql', description: 'Brazilian PII in code', evidence: '123.•••', recommendation: 'Remove PII from source.' },
      { id: '10', ruleId: 'rls_missing', severity: 'critical', title: 'RLS missing: orders', vector: 'rls_missing', source: 'supabase', description: 'Orders exposed', evidence: 'orders table open', recommendation: 'Enable RLS.' },
    ]),
    makeDemoProject('Landing Page Startup', '2025-06-15', '2025-12-20', 'vulnerable', 'protected', false, 'not_tested', 12, 0, [
      { id: '11', ruleId: 'bola_files', severity: 'critical', title: 'Exposure: Files accessible', vector: 'bola_files', source: 'api', description: 'Source exposed', evidence: 'HTTP 200', recommendation: 'Contact Lovable.' },
      { id: '12', ruleId: 'generic_api_key', severity: 'medium', title: 'API Key in config', vector: 'hardcoded_secret', source: 'config.ts', description: 'Generic key found', evidence: 'api_k•••', recommendation: 'Move to env vars.' },
    ]),
    makeDemoProject('CRM Dashboard', '2025-06-15', '2026-04-10', 'protected', 'protected', true, 'enabled', 30, 89, [
      { id: '13', ruleId: 'email', severity: 'medium', title: 'Email in constants', vector: 'pii_in_code', source: 'constants.ts', description: 'Email found', evidence: 'admin•••', recommendation: 'Remove hardcoded email.' },
      { id: '14', ruleId: 'firebase_key', severity: 'high', title: 'Firebase Key', vector: 'hardcoded_secret', source: 'firebase.ts', description: 'Firebase key exposed', evidence: 'AIza•••', recommendation: 'Restrict in Firebase console.' },
    ]),
    makeDemoProject('Blog Pessoal', '2026-03-01', '2026-04-10', 'protected', 'protected', false, 'not_tested', 15, 45, []),
  ];
}

function makeDemoProject(name, created, updated, bolaFile, bolaChat, supabase, rls, files, msgs, findings) {
  const result = {
    projectId: crypto.randomUUID(), projectName: name,
    createdAt: created, updatedAt: updated,
    scanTimestamp: new Date().toISOString(), scanDurationMs: Math.random() * 5000,
    bolaFileStatus: bolaFile, bolaChatStatus: bolaChat,
    supabaseDetected: supabase, supabaseUrl: supabase ? `https://${crypto.randomUUID().slice(0,20)}.supabase.co` : null,
    rlsStatus: rls, findings, filesScanned: files, chatMessagesScanned: msgs,
    riskScore: 0, severity: 'clean',
  };
  result.riskScore = computeRiskScore(result);
  result.severity = getSeverity(result.riskScore);
  return result;
}
