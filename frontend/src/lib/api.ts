import type { AnalysisDoc } from './types';

const SESSION_STORAGE_KEY = 'KAVACH_SESSION_ID';
const SESSION_HEADER = 'X-Kavach-Session';

const getApiUrl = (): string => {
  if (typeof window === 'undefined') return '';

  // 1. Check localStorage first for manual user override
  const savedApi = window.localStorage.getItem('KAVACH_API_URL');
  if (savedApi !== null) return savedApi;

  // 2. Check query parameters for manual override or toggle
  const params = new URLSearchParams(window.location.search);
  const paramApi = params.get('api_url');
  if (paramApi) {
    window.localStorage.setItem('KAVACH_API_URL', paramApi);
    return paramApi;
  }
  if (params.get('local') === 'true') {
    window.localStorage.setItem('KAVACH_API_URL', 'http://localhost:8080');
    return 'http://localhost:8080';
  }
  if (params.get('local') === 'false') {
    window.localStorage.setItem('KAVACH_API_URL', '');
    return '';
  }

  // 3. Allow build-time env variable override
  if (process.env.NEXT_PUBLIC_API_BASE_URL) {
    return process.env.NEXT_PUBLIC_API_BASE_URL;
  }
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }

  // 4. Default for local hostname development
  const hostname = window.location.hostname;
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:8080';
  }

  // Non-local host: use same-origin (frontend and backend served from same domain/reverse proxy)
  // To override, set NEXT_PUBLIC_API_BASE_URL at build time or use ?api_url= query param
  return '';
};

const API = getApiUrl();

export interface AnalysisStartResponse {
  id: string;
  status: string;
  [key: string]: unknown;
}

export interface DynamicAnalysisResponse {
  status: string;
}

function generateSessionId(): string {
  const randomPart = globalThis.crypto?.randomUUID?.().replace(/-/g, '') ?? `${Date.now()}${Math.random().toString(36).slice(2)}`;
  return `sess_${randomPart}`;
}

export function getClientSessionId(): string {
  if (typeof window === 'undefined') return '';

  const existing = window.localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) return existing;

  const created = generateSessionId();
  window.localStorage.setItem(SESSION_STORAGE_KEY, created);
  return created;
}

class IndexedDBCache {
  private dbName = 'KavachCache';
  private dbVersion = 1;
  private storeName = 'scans';

  private openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      if (typeof window === 'undefined') {
        reject(new Error('IndexedDB is not available server-side'));
        return;
      }
      const request = window.indexedDB.open(this.dbName, this.dbVersion);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'id' });
        }
      };
    });
  }

  async put(doc: any): Promise<void> {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readwrite');
        const store = tx.objectStore(this.storeName);
        const req = store.put(doc);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve();
      });
    } catch (err) {
      console.warn('Failed to write to IndexedDB cache:', err);
    }
  }

  async get(id: string): Promise<any | null> {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readonly');
        const store = tx.objectStore(this.storeName);
        const req = store.get(id);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve(req.result || null);
      });
    } catch (err) {
      console.warn('Failed to read from IndexedDB cache:', err);
      return null;
    }
  }

  async getAll(): Promise<any[]> {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readonly');
        const store = tx.objectStore(this.storeName);
        const req = store.getAll();
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve(req.result || []);
      });
    } catch (err) {
      console.warn('Failed to read history from IndexedDB cache:', err);
      return [];
    }
  }
}

export const indexedDbCache = new IndexedDBCache();

// No-auth fetch — Firebase suspended, open access for hackathon demo
export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json');
  }
  const sessionId = getClientSessionId();
  if (sessionId && !headers.has(SESSION_HEADER)) {
    headers.set(SESSION_HEADER, sessionId);
  }
  const url = path.startsWith('http') ? path : `${API}${path}`;

  const isGet = !init.method || init.method.toUpperCase() === 'GET';
  const isHistory = path === '/api/history';
  const isAnalysisMatch = path.startsWith('/api/analysis/');

  if (isGet && (isHistory || isAnalysisMatch)) {
    try {
      const res = await fetch(url, { ...init, headers });
      if (res.ok) {
        const clone = res.clone();
        try {
          const data = await clone.json();
          if (isHistory && Array.isArray(data)) {
            for (const doc of data) {
              await indexedDbCache.put(doc);
            }
          } else if (isAnalysisMatch && data && typeof data === 'object') {
            await indexedDbCache.put(data);
          }
        } catch (err) {
          console.warn('Failed to parse and cache Response in IndexedDB:', err);
        }
      }
      return res;
    } catch (err) {
      console.warn(`Network failure for GET ${path}, checking IndexedDB cache:`, err);
      if (isHistory) {
        const cachedDocs = await indexedDbCache.getAll();
        if (cachedDocs && cachedDocs.length > 0) {
          return new Response(JSON.stringify(cachedDocs), {
            status: 200,
            headers: new Headers({ 'Content-Type': 'application/json' })
          });
        }
      } else if (isAnalysisMatch) {
        const parts = path.split('/');
        const id = parts[parts.length - 1];
        const cachedDoc = await indexedDbCache.get(id);
        if (cachedDoc) {
          return new Response(JSON.stringify(cachedDoc), {
            status: 200,
            headers: new Headers({ 'Content-Type': 'application/json' })
          });
        }
      }
      throw err;
    }
  }

  return fetch(url, { ...init, headers });
}

export async function fetchSandboxHealth(): Promise<{ sandbox_status?: string }> {
  try {
    const res = await apiFetch('/api/sandbox-health');
    if (!res.ok) return { sandbox_status: 'UNAVAILABLE' };
    return res.json();
  } catch {
    return { sandbox_status: 'UNAVAILABLE' };
  }
}

export async function downloadReport(analysisId: string) {
  const res = await apiFetch(`/api/analysis/${analysisId}/report`);
  if (!res.ok) throw new Error('Report export failed');
  const data = await res.json();
  const blob = new Blob([data.content], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `kavach-report-${analysisId.slice(0, 8)}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export async function sendChat(analysisId: string, message: string): Promise<string> {
  const res = await apiFetch('/api/chat', {
    method: 'POST',
    body: JSON.stringify({ analysis_id: analysisId, message }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Chat failed');
  return data.answer as string;
}

export async function triggerDynamicAnalysis(analysisId: string, uid: string): Promise<DynamicAnalysisResponse> {
  const res = await apiFetch(`/api/analysis/${analysisId}/dynamic`, {
    method: 'POST',
    body: JSON.stringify({ uid }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Dynamic analysis failed to start.');
  return data as DynamicAnalysisResponse;
}

export const isLocalAPI = typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

export function uploadApkDirect(
  file: File,
  email: string | null,
  uid: string | null,
  onProgress?: (pct: number) => void
): Promise<AnalysisStartResponse> {
  return new Promise((resolve, reject) => {
    const formData = new FormData();
    formData.append('file', file);
    if (email) formData.append('email', email);
    if (uid) formData.append('uid', uid);

    const xhr = new XMLHttpRequest();
    const url = `${API}/api/analyze/upload?background=true`;

    xhr.open('POST', url, true);
    xhr.setRequestHeader(SESSION_HEADER, getClientSessionId());

    if (onProgress) {
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          const percentComplete = Math.round((event.loaded / event.total) * 100);
          onProgress(percentComplete);
        }
      };
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const data = JSON.parse(xhr.responseText);
          resolve(data as AnalysisStartResponse);
        } catch (err) {
          reject(new Error('Invalid JSON response from server'));
        }
      } else {
        try {
          const data = JSON.parse(xhr.responseText);
          reject(new Error(data.detail || 'Direct upload analysis failed.'));
        } catch {
          reject(new Error(`Upload failed with status ${xhr.status}`));
        }
      }
    };

    xhr.onerror = () => {
      reject(new Error('Network error during upload.'));
    };

    xhr.send(formData);
  });
}

export async function fetchHistory(): Promise<AnalysisDoc[]> {
  const res = await apiFetch('/api/history');
  if (!res.ok) throw new Error('Failed to fetch history');
  return res.json();
}

export function printExecutiveReport(doc: AnalysisDoc) {
  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    alert('Please allow popups to export the PDF report.');
    return;
  }

  const threatColor = {
    SAFE: '#10B981',
    LOW: '#3B82F6',
    MEDIUM: '#F59E0B',
    HIGH: '#EF4444',
    CRITICAL: '#7F1D1D'
  }[doc.threat_level || 'SAFE'];

  const badgesHtml = doc.banking_fraud?.badges?.map(b => `
    <div class="badge-item" style="border-left: 4px solid ${b.severity === 'CRITICAL' ? '#7F1D1D' : b.severity === 'HIGH' ? '#EF4444' : '#F59E0B'}; margin-bottom: 12px; padding: 12px; background-color: #F9FAFB; border-radius: 8px;">
      <strong style="color: #111827;">${b.title}</strong> <span style="font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; background-color: ${b.severity === 'CRITICAL' || b.severity === 'HIGH' ? '#FEE2E2' : '#FEF3C7'}; color: ${b.severity === 'CRITICAL' || b.severity === 'HIGH' ? '#991B1B' : '#92400E'};">${b.severity}</span>
      <p style="margin: 4px 0 0 0; font-size: 14px; color: #4B5563;">${b.summary}</p>
    </div>
  `).join('') || '<p style="color: #6B7280; font-style: italic;">No banking fraud indicators triggered.</p>';

  const vulnsHtml = doc.investigation_report?.code_vulnerabilities?.map(v => `
    <tr>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB;"><strong>${v.title}</strong></td>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB;"><span class="sev-tag ${v.severity?.toLowerCase()}" style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; ${v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'background-color: #FEE2E2; color: #991B1B;' : 'background-color: #FEF3C7; color: #92400E;'}">${v.severity}</span></td>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB; color: #4B5563;">${v.description}</td>
    </tr>
  `).join('') || '<tr><td colspan="3" style="padding: 12px; border-bottom: 1px solid #E5E7EB; color: #6B7280; font-style: italic; text-align: center;">No code vulnerabilities detected.</td></tr>';

  const activitiesHtml = doc.investigation_report?.suspicious_activities?.map(s => `
    <tr>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB;"><strong>${s.title}</strong></td>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB;"><span class="sev-tag ${s.severity?.toLowerCase()}" style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; ${s.severity === 'CRITICAL' || s.severity === 'HIGH' ? 'background-color: #FEE2E2; color: #991B1B;' : 'background-color: #FEF3C7; color: #92400E;'}">${s.severity}</span></td>
      <td style="padding: 12px; border-bottom: 1px solid #E5E7EB; color: #4B5563;">${s.description}</td>
    </tr>
  `).join('') || '<tr><td colspan="3" style="padding: 12px; border-bottom: 1px solid #E5E7EB; color: #6B7280; font-style: italic; text-align: center;">No suspicious activities detected.</td></tr>';

  const recsHtml = doc.investigation_report?.recommendations?.map(r => `
    <li style="margin-bottom: 8px;">${r}</li>
  `).join('') || '<li style="margin-bottom: 8px; color: #6B7280; font-style: italic;">No general recommendations. Monitor system behavior.</li>';

  const mitigationHtml = doc.banking_fraud?.recommended_actions?.map(m => `
    <li style="margin-bottom: 8px;">${m}</li>
  `).join('') || '<li style="margin-bottom: 8px; color: #6B7280; font-style: italic;">Standard Android sandbox security rules apply.</li>';

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Kavach AI Executive Report - ${doc.filename || 'Scan'}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@400;500;700&display=swap');
    body {
      font-family: 'Outfit', sans-serif;
      color: #1F2937;
      margin: 40px;
      line-height: 1.5;
      background-color: #ffffff;
    }
    h1, h2, h3 {
      font-family: 'Space Grotesk', sans-serif;
      color: #111827;
      margin-top: 0;
    }
    .header-table {
      width: 100%;
      border-bottom: 2px solid #E5E7EB;
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    .score-box {
      border: 2px solid #E5E7EB;
      border-radius: 12px;
      padding: 16px;
      text-align: center;
      background-color: #F9FAFB;
      width: 160px;
    }
    .score-number {
      font-size: 44px;
      font-weight: 800;
      line-height: 1;
      margin: 8px 0;
    }
    .threat-tag {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      color: white;
      font-weight: 700;
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: 0.05em;
    }
    .meta-label {
      color: #6B7280;
      font-weight: 500;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .meta-value {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .section-title {
      border-bottom: 2px solid #E5E7EB;
      padding-bottom: 8px;
      margin-top: 40px;
      margin-bottom: 20px;
      font-size: 20px;
      font-weight: 700;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 30px;
    }
    th {
      text-align: left;
      padding: 12px;
      border-bottom: 2px solid #E5E7EB;
      background-color: #F3F4F6;
      font-weight: 600;
      color: #374151;
    }
    .footer {
      margin-top: 60px;
      border-top: 1px solid #E5E7EB;
      padding-top: 20px;
      font-size: 12px;
      color: #9CA3AF;
      text-align: center;
    }
    @media print {
      body { margin: 20px; background-color: #fff; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
    .btn-print {
      display: inline-block;
      background-color: #1F2937;
      color: white;
      padding: 10px 20px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      border: none;
      transition: background-color 0.2s;
    }
    .btn-print:hover {
      background-color: #374151;
    }
  </style>
</head>
<body>
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;" class="no-print">
    <span style="font-size: 14px; color: #6B7280; font-weight: 500;">Kavach AI Security Report Export</span>
    <button class="btn-print" onclick="window.print()">Print / Save PDF</button>
  </div>

  <table class="header-table" style="border-collapse: collapse; width: 100%; border-bottom: 2px solid #E5E7EB; margin-bottom: 30px;">
    <tr>
      <td style="border: none; padding: 0; vertical-align: middle;">
        <h1 style="font-size: 32px; font-weight: 800; letter-spacing: -0.02em; margin: 0 0 4px 0; color: #111827;">KAVACH AI</h1>
        <div style="font-size: 16px; color: #4B5563; font-weight: 500;">Automated Mobile Malware & Fraud Intelligence</div>
        <div style="font-size: 12px; color: #9CA3AF; margin-top: 12px; font-family: monospace;">ID: ${doc.id}</div>
      </td>
      <td style="border: none; padding: 0; vertical-align: middle; width: 180px;" align="right">
        <div class="score-box">
          <div class="meta-label">Risk Index</div>
          <div class="score-number" style="color: ${threatColor};">${doc.risk_score || 0}</div>
          <div class="threat-tag" style="background-color: ${threatColor};">${doc.threat_level || 'SAFE'}</div>
        </div>
      </td>
    </tr>
  </table>

  <h2 class="section-title">1. App Identity Details</h2>
  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
    <div>
      <div class="meta-label">App Filename</div>
      <div class="meta-value">${doc.filename || 'Unknown'}</div>
    </div>
    <div>
      <div class="meta-label">Android Package Name</div>
      <div class="meta-value" style="font-family: monospace;">${doc.package_name || 'N/A'}</div>
    </div>
  </div>

  <h2 class="section-title">2. Analysis Summary Narrative</h2>
  
  <h3 style="font-size: 16px; margin-top: 15px; font-weight: 700; color: #1F2937; border-bottom: 1px solid #F3F4F6; padding-bottom: 4px;">🔧 Security Operations (SOC) Summary</h3>
  <p style="font-size: 14px; line-height: 1.6; color: #4B5563; white-space: pre-line; margin-bottom: 20px;">
    ${doc.investigation_report?.summary || doc.static_analysis?.investigation_report?.summary || 'No SOC summary compiled.'}
  </p>

  <h3 style="font-size: 16px; margin-top: 15px; font-weight: 700; color: #B45309; border-bottom: 1px solid #FDF2E9; padding-bottom: 4px;">🏦 Bank frontline Agent Alert</h3>
  <p style="font-size: 14px; line-height: 1.6; color: #78350F; white-space: pre-line; margin-bottom: 20px; padding: 12px; background-color: #FEF3C7; border-left: 4px solid #F59E0B; border-radius: 6px;">
    ${doc.investigation_report?.bank_agent_alert || doc.static_analysis?.investigation_report?.bank_agent_alert || 'No frontline warning compiled.'}
  </p>

  <h3 style="font-size: 16px; margin-top: 15px; font-weight: 700; color: #111827; border-bottom: 1px solid #F3F4F6; padding-bottom: 4px;">📋 CISO Executive Brief</h3>
  <p style="font-size: 14px; line-height: 1.6; color: #374151; white-space: pre-line; margin-bottom: 20px; padding: 12px; background-color: #F9FAFB; border-left: 4px solid #4B5563; border-radius: 6px;">
    ${doc.investigation_report?.ciso_brief || doc.static_analysis?.investigation_report?.ciso_brief || 'No executive brief compiled.'}
  </p>

  ${(doc.investigation_report?.dynamic_summary || doc.investigation_report?.final_report) ? `
    <h3 style="font-size: 16px; margin-top: 20px; font-weight: 700; color: #111827; border-bottom: 1px solid #F3F4F6; padding-bottom: 4px;">Behavioral Sandbox Audit & Combined Advisory:</h3>
    <p style="font-size: 14px; line-height: 1.6; color: #4B5563; white-space: pre-line; margin-bottom: 20px;">
      ${doc.investigation_report?.final_report || doc.investigation_report?.dynamic_summary || ''}
    </p>
  ` : ''}

  <h2 class="section-title">3. Banking & Financial Fraud Indicators</h2>
  <div style="margin-bottom: 30px;">
    <div style="display: flex; align-items: center; margin-bottom: 15px;">
      <span class="meta-label" style="margin-right: 15px; margin-bottom: 0;">Fraud Exposure Index:</span>
      <strong style="font-size: 18px; color: ${doc.banking_fraud?.fraud_score && doc.banking_fraud.fraud_score >= 50 ? '#EF4444' : '#F59E0B'}">${doc.banking_fraud?.fraud_score ?? 0}/100</strong>
    </div>
    ${badgesHtml}
  </div>

  <div class="page-break"></div>

  <h2 class="section-title">4. Code Vulnerability & Threat Findings</h2>
  
  <h3 style="font-size: 16px; font-weight: 700; margin-top: 20px; margin-bottom: 10px;">Static Code Vulnerabilities</h3>
  <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px;">
    <thead>
      <tr>
        <th style="width: 25%;">Vulnerability</th>
        <th style="width: 15%;">Severity</th>
        <th style="width: 60%;">Context & Description</th>
      </tr>
    </thead>
    <tbody>
      ${vulnsHtml}
    </tbody>
  </table>

  <h3 style="font-size: 16px; font-weight: 700; margin-top: 20px; margin-bottom: 10px;">Suspicious Activities & Behavioral Signals</h3>
  <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px;">
    <thead>
      <tr>
        <th style="width: 25%;">Activity</th>
        <th style="width: 15%;">Severity</th>
        <th style="width: 60%;">Indicator Detail</th>
      </tr>
    </thead>
    <tbody>
      ${activitiesHtml}
    </tbody>
  </table>

  <h2 class="section-title">5. Actions & Threat Mitigation</h2>
  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-top: 20px;">
    <div>
      <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px; color: #111827;">General Actions</h3>
      <ul style="padding-left: 20px; margin: 0; color: #374151;">
        ${recsHtml}
      </ul>
    </div>
    <div>
      <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px; color: #111827;">Banking Mitigation Protocol</h3>
      <ul style="padding-left: 20px; margin: 0; color: #374151;">
        ${mitigationHtml}
      </ul>
    </div>
  </div>

  <div class="footer">
    KAVACH AI Mobile Threat Shield Audit Report. Prepared for Bank of India by Kavach Core Engines.
  </div>
</body>
</html>
  `;

  printWindow.document.write(html);
  printWindow.document.close();
}
