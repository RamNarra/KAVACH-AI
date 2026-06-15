import type { AnalysisDoc } from './types';

const SESSION_STORAGE_KEY = 'KAVACH_SESSION_ID';
const SESSION_HEADER = 'X-Kavach-Session';

const getApiUrl = (): string => {
  if (typeof window === 'undefined') return '';

  // 1. Check localStorage first for manual user override
  const savedApi = window.localStorage.getItem('KAVACH_API_URL');
  if (savedApi !== null && savedApi !== '') return savedApi;

  // 2. Check query parameters for manual override or toggle
  const params = new URLSearchParams(window.location.search);
  const paramApi = params.get('api_url');
  if (paramApi) {
    window.localStorage.setItem('KAVACH_API_URL', paramApi);
    return paramApi;
  }
  if (params.get('local') === 'true') {
    window.localStorage.setItem('KAVACH_API_URL', 'http://127.0.0.1:8080');
    return 'http://127.0.0.1:8080';
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
    return 'http://127.0.0.1:8080';
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

  async put(doc: AnalysisDoc): Promise<void> {
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

  async get(id: string): Promise<AnalysisDoc | null> {
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

  async getAll(): Promise<AnalysisDoc[]> {
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

// No-auth fetch — Open access fallback for hackathon demo
export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json');
  }
  const sessionId = getClientSessionId();
  if (sessionId && !headers.has(SESSION_HEADER)) {
    headers.set(SESSION_HEADER, sessionId);
  }
  // Inject dynamic JWT authorization header if present
  if (typeof window !== 'undefined') {
    const jwtToken = window.sessionStorage.getItem('KAVACH_JWT_TOKEN');
    if (jwtToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${jwtToken}`);
    }
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

export async function cancelAnalysis(analysisId: string): Promise<void> {
  const res = await apiFetch(`/api/analysis/${analysisId}/cancel`, {
    method: 'POST',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || 'Failed to cancel analysis.');
  }
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

    if (typeof window !== 'undefined') {
      const jwtToken = window.sessionStorage.getItem('KAVACH_JWT_TOKEN');
      if (jwtToken) {
        xhr.setRequestHeader('Authorization', `Bearer ${jwtToken}`);
      }
    }

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
        } catch {
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
    CRITICAL: '#B91C1C'
  }[doc.threat_level || 'SAFE'];

  const badgesHtml = doc.banking_fraud?.badges?.map(b => `
    <div class="badge-item" style="border-left: 4px solid ${b.severity === 'CRITICAL' ? '#B91C1C' : b.severity === 'HIGH' ? '#EF4444' : '#F59E0B'}; margin-bottom: 16px; padding: 16px; background-color: #111126; border-radius: 12px; border: 1px solid #222244; border-left-width: 5px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <strong style="color: #F3F4F6; font-size: 15px;">${b.title}</strong> 
        <span style="font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 6px; text-transform: uppercase; background-color: ${b.severity === 'CRITICAL' || b.severity === 'HIGH' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)'}; color: ${b.severity === 'CRITICAL' || b.severity === 'HIGH' ? '#F87171' : '#FBBF24'}; border: 1px solid ${b.severity === 'CRITICAL' || b.severity === 'HIGH' ? 'rgba(239,68,68,0.3)' : 'rgba(245,158,11,0.3)'};">${b.severity}</span>
      </div>
      <p style="margin: 0; font-size: 13.5px; color: #9CA3AF; line-height: 1.5;">${b.summary}</p>
    </div>
  `).join('') || '<p style="color: #6B7280; font-style: italic; text-align: center; padding: 20px; background-color: #111126; border: 1px solid #222244; border-radius: 12px;">No banking fraud indicators triggered.</p>';

  const vulnsHtml = doc.investigation_report?.code_vulnerabilities?.map(v => `
    <tr>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244; color: #F3F4F6;"><strong>${v.title}</strong></td>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244;"><span class="sev-tag ${v.severity?.toLowerCase()}" style="font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 6px; text-transform: uppercase; ${v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'background-color: rgba(239,68,68,0.15); color: #F87171; border: 1px solid rgba(239,68,68,0.3);' : 'background-color: rgba(245,158,11,0.15); color: #FBBF24; border: 1px solid rgba(245,158,11,0.3);'}">${v.severity}</span></td>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244; color: #9CA3AF; font-size: 13.5px; line-height: 1.5;">${v.description}</td>
    </tr>
  `).join('') || '<tr><td colspan="3" style="padding: 20px; border-bottom: 1px solid #222244; color: #6B7280; font-style: italic; text-align: center; background-color: #111126;">No code vulnerabilities detected.</td></tr>';

  const activitiesHtml = doc.investigation_report?.suspicious_activities?.map(s => `
    <tr>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244; color: #F3F4F6;"><strong>${s.title}</strong></td>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244;"><span class="sev-tag ${s.severity?.toLowerCase()}" style="font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 6px; text-transform: uppercase; ${s.severity === 'CRITICAL' || s.severity === 'HIGH' ? 'background-color: rgba(239,68,68,0.15); color: #F87171; border: 1px solid rgba(239,68,68,0.3);' : 'background-color: rgba(245,158,11,0.15); color: #FBBF24; border: 1px solid rgba(245,158,11,0.3);'}">${s.severity}</span></td>
      <td style="padding: 14px 12px; border-bottom: 1px solid #222244; color: #9CA3AF; font-size: 13.5px; line-height: 1.5;">${s.description}</td>
    </tr>
  `).join('') || '<tr><td colspan="3" style="padding: 20px; border-bottom: 1px solid #222244; color: #6B7280; font-style: italic; text-align: center; background-color: #111126;">No suspicious activities detected.</td></tr>';

  const recsHtml = doc.investigation_report?.recommendations?.map(r => `
    <li style="margin-bottom: 10px; line-height: 1.5; font-size: 14px;">${r}</li>
  `).join('') || '<li style="margin-bottom: 10px; color: #6B7280; font-style: italic; font-size: 14px;">No general recommendations. Monitor system behavior.</li>';

  const mitigationHtml = doc.banking_fraud?.recommended_actions?.map(m => `
    <li style="margin-bottom: 10px; line-height: 1.5; font-size: 14px;">${m}</li>
  `).join('') || '<li style="margin-bottom: 10px; color: #6B7280; font-style: italic; font-size: 14px;">Standard Android sandbox security rules apply.</li>';

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Kavach AI Executive Threat Report - ${doc.filename || 'Scan'}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@400;500;700&display=swap');
    
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }
    
    body {
      font-family: 'Outfit', sans-serif;
      color: #E5E7EB;
      margin: 40px;
      line-height: 1.6;
      background-color: #080810;
      background-image: radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.04) 0%, transparent 40%),
                        radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.04) 0%, transparent 40%);
      background-attachment: fixed;
    }
    
    h1, h2, h3, h4 {
      font-family: 'Space Grotesk', sans-serif;
      color: #F3F4F6;
      margin-top: 0;
      letter-spacing: -0.01em;
    }
    
    .header-container {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #222244;
      padding-bottom: 24px;
      margin-bottom: 35px;
    }
    
    .logo-area {
      display: flex;
      align-items: center;
      gap: 15px;
    }
    
    .score-box {
      border: 1.5px solid #222244;
      border-radius: 16px;
      padding: 18px;
      text-align: center;
      background-color: #111126;
      width: 175px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4), inset 0 0 10px rgba(59, 130, 246, 0.05);
    }
    
    .score-number {
      font-size: 48px;
      font-weight: 800;
      line-height: 1;
      margin: 6px 0;
      font-family: 'Space Grotesk', sans-serif;
      text-shadow: 0 0 12px rgba(255, 255, 255, 0.1);
    }
    
    .threat-tag {
      display: inline-block;
      padding: 5px 14px;
      border-radius: 20px;
      color: white;
      font-weight: 700;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.08em;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    }
    
    .meta-label {
      color: #9CA3AF;
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }
    
    .meta-value {
      font-size: 15px;
      font-weight: 600;
      color: #F3F4F6;
      font-family: monospace;
    }
    
    .section-title {
      border-bottom: 1px solid #222244;
      padding-bottom: 10px;
      margin-top: 45px;
      margin-bottom: 22px;
      font-size: 20px;
      font-weight: 700;
      color: #60A5FA;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    
    .glass-card {
      background: #111126;
      border: 1px solid #222244;
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 30px;
      background-color: #111126;
      border: 1px solid #222244;
      border-radius: 12px;
      overflow: hidden;
    }
    
    th {
      text-align: left;
      padding: 14px 12px;
      border-bottom: 2px solid #222244;
      background-color: #151530;
      font-weight: 600;
      color: #9CA3AF;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .footer {
      margin-top: 70px;
      border-top: 1px solid #222244;
      padding-top: 25px;
      font-size: 11.5px;
      color: #6B7280;
      text-align: center;
      font-weight: 500;
    }
    
    @media print {
      body {
        margin: 20px;
        background-color: #080810 !important;
        color: #E5E7EB !important;
      }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
      .glass-card, .score-box, table, th, td, .badge-item {
        background-color: #111126 !important;
        border-color: #222244 !important;
      }
    }
    @media (max-width: 640px) {
      .header-container {
        flex-direction: column;
        align-items: flex-start;
        gap: 20px;
      }
      .glass-card {
        grid-template-columns: 1fr !important;
      }
      body {
        margin: 15px;
      }
    }
    
    .btn-print {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background-color: #3B82F6;
      color: white;
      padding: 10px 22px;
      border-radius: 9999px;
      text-decoration: none;
      font-weight: 700;
      font-size: 13.5px;
      cursor: pointer;
      border: none;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
      transition: all 0.2s ease;
    }
    
    .btn-print:hover {
      background-color: #2563EB;
      box-shadow: 0 6px 20px rgba(59, 130, 246, 0.6);
      transform: translateY(-1px);
    }
  </style>
</head>
<body>
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; background: rgba(17,17,38,0.6); padding: 12px 20px; border-radius: 12px; border: 1px solid #222244;" class="no-print">
    <span style="font-size: 13px; color: #9CA3AF; font-weight: 600; tracking: 0.05em; text-transform: uppercase;">Kavach AI Threat Shield Export</span>
    <button class="btn-print" onclick="window.print()">
      <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
      Print / Save PDF
    </button>
  </div>

  <div class="header-container">
    <div class="logo-area">
      <svg width="42" height="48" viewBox="0 0 100 115" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M50 0L95.5 25V65C95.5 92.5 75.5 110 50 115C24.5 110 4.5 92.5 4.5 65V25L50 0Z" fill="url(#shield_grad)" stroke="#3B82F6" stroke-width="6" stroke-linejoin="round"/>
        <path d="M50 30V85M35 55L50 70L65 55" stroke="#F3F4F6" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
        <defs>
          <linearGradient id="shield_grad" x1="50" y1="0" x2="50" y2="115" gradientUnits="userSpaceOnUse">
            <stop stop-color="#1E40AF" stop-opacity="0.95"/>
            <stop offset="1" stop-color="#0F172A" stop-opacity="0.95"/>
          </linearGradient>
        </defs>
      </svg>
      <div>
        <h1 style="font-size: 28px; font-weight: 800; letter-spacing: 0.05em; margin: 0; color: #FFFFFF; text-shadow: 0 0 15px rgba(59, 130, 246, 0.3);">KAVACH AI</h1>
        <div style="font-size: 13px; color: #60A5FA; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; margin-top: 3px;">Automated Mobile Malware & Banking Fraud Intelligence</div>
      </div>
    </div>
    <div class="score-box">
      <div class="meta-label" style="color: #60A5FA;">Risk Index</div>
      <div class="score-number" style="color: ${threatColor};">${doc.risk_score || 0}<span style="font-size: 16px; color: #4B5563; font-weight: 500;">/100</span></div>
      <div class="threat-tag" style="background-color: ${threatColor};">${doc.threat_level || 'SAFE'}</div>
    </div>
  </div>

  <h2 class="section-title" style="margin-top: 0;">1. App Identity Details</h2>
  <div class="glass-card" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
    <div>
      <div class="meta-label">App Filename</div>
      <div class="meta-value" style="color: #F3F4F6; font-size: 14px; font-family: sans-serif;">${doc.filename || 'Unknown'}</div>
    </div>
    <div>
      <div class="meta-label">Android Package Name</div>
      <div class="meta-value" style="font-family: monospace; color: #60A5FA; font-size: 13.5px;">${doc.package_name || 'N/A'}</div>
    </div>
  </div>

  <h2 class="section-title">2. Automated Generative AI Security Advisories</h2>
  
  <div style="display: grid; grid-template-columns: 1fr; gap: 20px; margin-bottom: 25px;">
    <div class="glass-card" style="border-left: 4px solid #10B981; background-color: rgba(16,185,129,0.02);">
      <h3 style="font-size: 15px; font-weight: 700; color: #34D399; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em;">⚙️ Reverse Engineering Insights</h3>
      <p style="font-size: 13.5px; line-height: 1.6; color: #D1D5DB; white-space: pre-line; margin: 0;">
        ${doc.investigation_report?.reverse_engineering_summary || doc.static_analysis?.investigation_report?.reverse_engineering_summary || doc.investigation_report?.summary || doc.static_analysis?.investigation_report?.summary || 'No reverse engineering insights compiled.'}
      </p>
    </div>

    <div class="glass-card" style="border-left: 4px solid #3B82F6; background-color: rgba(59,130,246,0.02);">
      <h3 style="font-size: 15px; font-weight: 700; color: #60A5FA; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em;">🔍 Static Security Audit Summary</h3>
      <p style="font-size: 13.5px; line-height: 1.6; color: #D1D5DB; white-space: pre-line; margin: 0;">
        ${doc.investigation_report?.static_analysis_summary || doc.static_analysis?.investigation_report?.static_analysis_summary || doc.investigation_report?.summary || doc.static_analysis?.investigation_report?.summary || 'No static analysis summary compiled.'}
      </p>
    </div>

    <div class="glass-card" style="border-left: 4px solid #818CF8; background-color: rgba(129,140,248,0.02);">
      <h3 style="font-size: 15px; font-weight: 700; color: #A5B4FC; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em;">⚡ Dynamic Sandbox Tracing Trace</h3>
      <p style="font-size: 13.5px; line-height: 1.6; color: #D1D5DB; white-space: pre-line; margin: 0;">
        ${doc.investigation_report?.dynamic_analysis_summary || doc.static_analysis?.investigation_report?.dynamic_analysis_summary || doc.investigation_report?.summary || doc.static_analysis?.investigation_report?.summary || 'No dynamic sandbox analysis summary compiled.'}
      </p>
    </div>
  </div>

  <h2 class="section-title">3. Banking & Financial Fraud Indicators</h2>
  <div class="glass-card" style="margin-bottom: 35px;">
    <div style="display: flex; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #222244; padding-bottom: 12px;">
      <span class="meta-label" style="margin-right: 15px; margin-bottom: 0; font-size: 12px;">Fraud Exposure Index:</span>
      <strong style="font-size: 20px; color: ${doc.banking_fraud?.fraud_score && doc.banking_fraud.fraud_score >= 50 ? '#EF4444' : '#FBBF24'}; font-family: 'Space Grotesk', sans-serif;">${doc.banking_fraud?.fraud_score ?? 0}/100</strong>
    </div>
    ${badgesHtml}
  </div>

  <div class="page-break"></div>

  <h2 class="section-title">4. Code Vulnerability & Threat Findings</h2>
  
  <h3 style="font-size: 15px; font-weight: 700; margin-top: 25px; margin-bottom: 12px; color: #60A5FA; text-transform: uppercase; letter-spacing: 0.05em;">Static Code Vulnerabilities</h3>
  <table>
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

  <h3 style="font-size: 15px; font-weight: 700; margin-top: 35px; margin-bottom: 12px; color: #60A5FA; text-transform: uppercase; letter-spacing: 0.05em;">Suspicious Activities & Behavioral Signals</h3>
  <table>
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
  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-top: 20px;">
    <div class="glass-card" style="border-top: 3.5px solid #10B981;">
      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 15px; color: #34D399; text-transform: uppercase; letter-spacing: 0.05em;">General Mitigation Plan</h3>
      <ul style="padding-left: 20px; margin: 0; color: #D1D5DB; line-height: 1.6;">
        ${recsHtml}
      </ul>
    </div>
    <div class="glass-card" style="border-top: 3.5px solid #10B981; background-color: rgba(16,185,129,0.02);">
      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 15px; color: #34D399; text-transform: uppercase; letter-spacing: 0.05em;">Banking Mitigation Protocol</h3>
      <ul style="padding-left: 20px; margin: 0; color: #D1D5DB; line-height: 1.6;">
        ${mitigationHtml}
      </ul>
    </div>
  </div>

  <div class="footer">
    KAVACH AI Mobile Threat Shield Audit Report · Joint Initiative IIT Hyderabad × Bank of India · Secured Output
  </div>
</body>
</html>
  `;

  printWindow.document.write(html);
  printWindow.document.close();
}

export function setAuthToken(token: string) {
  if (typeof window !== 'undefined') {
    window.sessionStorage.setItem('KAVACH_JWT_TOKEN', token);
  }
}

export function getAuthToken(): string | null {
  if (typeof window !== 'undefined') {
    return window.sessionStorage.getItem('KAVACH_JWT_TOKEN');
  }
  return null;
}

export function clearAuthToken() {
  if (typeof window !== 'undefined') {
    window.sessionStorage.removeItem('KAVACH_JWT_TOKEN');
  }
}

export function isTokenValid(token: string): boolean {
  if (!token) return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1]));
    const exp = payload.exp;
    if (exp && Date.now() >= exp * 1000) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export async function loginUser(email: string, password: string): Promise<{ token: string; uid: string; username: string }> {
  const res = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to login');
  }
  const data = await res.json();
  if (typeof window !== 'undefined') {
    window.sessionStorage.setItem('KAVACH_JWT_TOKEN', data.token);
    window.sessionStorage.setItem('KAVACH_USERNAME', data.username);
  }
  return data;
}

export async function registerUser(
  email: string,
  password: string,
  firstName: string,
  lastName: string,
  geminiApiKey?: string
): Promise<{ token: string; uid: string; username: string }> {
  const res = await fetch(`${API}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      first_name: firstName,
      last_name: lastName,
      gemini_api_key: geminiApiKey || null
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to register');
  }
  const data = await res.json();
  if (typeof window !== 'undefined') {
    window.sessionStorage.setItem('KAVACH_JWT_TOKEN', data.token);
    window.sessionStorage.setItem('KAVACH_USERNAME', data.username);
  }
  return data;
}

export async function updateGeminiApiKey(geminiApiKey: string | null): Promise<any> {
  const token = getAuthToken();
  const res = await fetch(`${API}/api/auth/update-key`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      gemini_api_key: geminiApiKey
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to update Gemini API Key');
  }
  return res.json();
}


export function getAnalysisStreamUrl(analysisId: string): string {
  const token = getAuthToken() || '';
  return `${API}/api/analysis/${analysisId}/stream?token=${token}`;
}
