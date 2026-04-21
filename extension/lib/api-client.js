// ============================================================
// Lovable Portfolio Audit — API Client (Chrome Extension)
// Uses chrome.cookies for automatic auth, bypasses CORS
// ============================================================

const API_BASE = 'https://api.lovable.dev';
const USER_AGENT = 'NXLV-Audit/1.0 (+https://github.com/lucioamorim/lovable-portfolio-audit)';

let sessionToken = null;
let lastRequestTime = 0;
let requestDelay = 500;

export function setDelay(ms) { requestDelay = Math.max(200, ms); }

export async function getSessionToken() {
  try {
    const cookie = await chrome.cookies.get({
      url: 'https://lovable.dev',
      name: '__lovable_session'
    });
    if (cookie?.value) {
      sessionToken = cookie.value;
      return sessionToken;
    }
    // Fallback: try other common cookie names
    for (const name of ['sb-access-token', 'supabase-auth-token', 'session']) {
      const alt = await chrome.cookies.get({ url: 'https://lovable.dev', name });
      if (alt?.value) { sessionToken = alt.value; return sessionToken; }
    }
    // Fallback: try to get from storage (manual input)
    const stored = await chrome.storage.local.get('lss_manual_token');
    if (stored.lss_manual_token) { sessionToken = stored.lss_manual_token; return sessionToken; }
    return null;
  } catch (e) {
    console.error('[LPI] Failed to get session:', e);
    return null;
  }
}

export function hasSession() { return !!sessionToken; }

async function throttle() {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < requestDelay) {
    await new Promise(r => setTimeout(r, requestDelay - elapsed));
  }
  lastRequestTime = Date.now();
}

async function apiRequest(path) {
  await throttle();
  const headers = { 'Content-Type': 'application/json', 'X-Client': USER_AGENT };
  if (sessionToken) {
    headers['Authorization'] = `Bearer ${sessionToken}`;
    headers['Cookie'] = `__lovable_session=${sessionToken}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { headers, credentials: 'include' });
  return res;
}

export async function listProjects() {
  const res = await apiRequest('/user/projects');
  if (!res.ok) throw new Error(`listProjects failed: ${res.status}`);
  return await res.json();
}

export async function probeEndpoint(path) {
  try {
    const res = await apiRequest(path);
    return { status: res.status, ok: res.ok, contentLength: parseInt(res.headers.get('content-length') || '0') };
  } catch { return { status: 0, ok: false, contentLength: 0 }; }
}

export async function getProjectFiles(projectId) {
  const res = await apiRequest(`/projects/${projectId}/git/files`);
  if (!res.ok) return null;
  return await res.json();
}

export async function getFileContent(projectId, filePath) {
  const res = await apiRequest(`/projects/${projectId}/git/files/${encodeURIComponent(filePath)}`);
  if (!res.ok) return null;
  return await res.text();
}

export async function getProjectMessages(projectId) {
  const res = await apiRequest(`/projects/${projectId}/messages`);
  if (!res.ok) return null;
  return await res.json();
}

export async function testBOLA(projectId) {
  const fileProbe = await probeEndpoint(`/projects/${projectId}/git/files`);
  const chatProbe = await probeEndpoint(`/projects/${projectId}/messages`);
  return {
    fileStatus: fileProbe.status === 200 ? 'vulnerable' : fileProbe.status === 403 ? 'protected' : 'unknown',
    chatStatus: chatProbe.status === 200 ? 'vulnerable' : chatProbe.status === 403 ? 'protected' : 'unknown',
  };
}
