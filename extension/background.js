// ============================================================
// Background Service Worker — Scan orchestrator
// ============================================================

import { runScan, abortScan, generateDemoData } from './lib/scanner-engine.js';
import { getSessionToken, hasSession } from './lib/api-client.js';

// Keep alive during long scans
let keepAliveInterval = null;

function startKeepAlive() {
  keepAliveInterval = setInterval(() => {
    // Ping to keep service worker alive during scan
  }, 25000);
}

function stopKeepAlive() {
  if (keepAliveInterval) { clearInterval(keepAliveInterval); keepAliveInterval = null; }
}

// Listen for messages from popup/sidepanel
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CHECK_SESSION') {
    getSessionToken().then(token => {
      sendResponse({ hasSession: !!token });
    });
    return true;
  }

  if (msg.type === 'START_SCAN') {
    startKeepAlive();
    runScan(
      msg.config || {},
      (progress) => {
        chrome.runtime.sendMessage({ type: 'SCAN_PROGRESS', progress }).catch(() => {});
      },
      (result) => {
        // Store result incrementally
        chrome.storage.local.get('lss_results', (data) => {
          const results = data.lss_results || [];
          results.push(result);
          chrome.storage.local.set({ lss_results: results });
        });
        chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result }).catch(() => {});
      }
    ).then(summary => {
      stopKeepAlive();
      chrome.storage.local.set({ lss_summary: summary });
      chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', summary }).catch(() => {});
      // Update badge
      const crit = summary.criticalCount;
      if (crit > 0) {
        chrome.action.setBadgeText({ text: String(crit) });
        chrome.action.setBadgeBackgroundColor({ color: '#ff4757' });
      } else {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#2ed573' });
      }
    }).catch(err => {
      stopKeepAlive();
      chrome.runtime.sendMessage({ type: 'SCAN_ERROR', error: err.message }).catch(() => {});
    });
    sendResponse({ started: true });
    return true;
  }

  if (msg.type === 'STOP_SCAN') {
    abortScan();
    stopKeepAlive();
    sendResponse({ stopped: true });
    return true;
  }

  if (msg.type === 'LOAD_DEMO') {
    const results = generateDemoData();
    const summary = {
      totalProjects: results.length, scannedProjects: results.length,
      criticalCount: results.filter(r => r.severity === 'critical').length,
      highCount: results.filter(r => r.severity === 'high').length,
      mediumCount: results.filter(r => r.severity === 'medium').length,
      lowCount: results.filter(r => r.severity === 'low').length,
      cleanCount: results.filter(r => r.severity === 'clean').length,
      topFindings: results.flatMap(r => r.findings).slice(0, 10),
      scanStartTime: new Date().toISOString(), scanEndTime: new Date().toISOString(),
      totalDurationMs: 22800,
    };
    chrome.storage.local.set({ lss_results: results, lss_summary: summary, lss_demo: true });
    sendResponse({ results, summary });
    return true;
  }

  if (msg.type === 'GET_RESULTS') {
    chrome.storage.local.get(['lss_results', 'lss_summary', 'lss_demo'], (data) => {
      sendResponse({
        results: data.lss_results || [],
        summary: data.lss_summary || null,
        isDemoMode: data.lss_demo || false,
      });
    });
    return true;
  }

  if (msg.type === 'CLEAR_RESULTS') {
    chrome.storage.local.remove(['lss_results', 'lss_summary', 'lss_demo']);
    chrome.action.setBadgeText({ text: '' });
    sendResponse({ cleared: true });
    return true;
  }
});

// Enable side panel
chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: false });

// On install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[LSS] Lovable Security Scanner installed');
});
