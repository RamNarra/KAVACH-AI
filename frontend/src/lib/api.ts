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

export async function uploadApkDirect(
  file: File,
  email: string | null,
  uid: string | null,
  onProgress?: (pct: number) => void
): Promise<AnalysisStartResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (email) formData.append('email', email);
  if (uid) formData.append('uid', uid);

  if (onProgress) onProgress(30);
  if (onProgress) onProgress(70);

  const url = `${API}/api/analyze/upload?background=true`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      [SESSION_HEADER]: getClientSessionId(),
    },
    body: formData,
  });
  if (onProgress) onProgress(100);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Direct upload analysis failed.');
  return data as AnalysisStartResponse;
}
