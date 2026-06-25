// API fetch helpers — all requests go through Next.js /api proxy
import { getAuthHeaders } from './auth';
import type { AuthResponse, AnalysisResult, HistoryItem } from './types';

const BASE = '/api';

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    ...getAuthHeaders(),
    ...(options.headers as Record<string, string> || {}),
  };

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const err = await res.json();
      detail = err.detail || err.message || detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<AuthResponse> {
  return request<AuthResponse>('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
}

export async function register(
  email: string,
  password: string,
  first_name: string,
  last_name: string,
  gemini_api_key?: string
): Promise<AuthResponse> {
  return request<AuthResponse>('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, first_name, last_name, gemini_api_key }),
  });
}

export async function updateGeminiKey(gemini_api_key: string | null): Promise<{ status: string; message: string }> {
  return request('/auth/update-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ gemini_api_key }),
  });
}

// ── Scan ──────────────────────────────────────────────────────────────────────

export async function scanByUrl(apk_url: string, uid?: string): Promise<{ id: string; status: string }> {
  return request('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apk_url, uid }),
  });
}

export async function scanByUpload(file: File, uid?: string): Promise<{ id: string; status: string }> {
  const form = new FormData();
  form.append('file', file);
  if (uid) form.append('uid', uid);
  return request('/analyze/upload', {
    method: 'POST',
    body: form,
    // headers intentionally omit Content-Type so browser sets multipart boundary
  });
}

// ── Analysis ──────────────────────────────────────────────────────────────────

export async function getAnalysis(id: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/analysis/${id}`);
}

export async function getHistory(): Promise<HistoryItem[]> {
  return request<HistoryItem[]>('/history');
}

export async function triggerDynamic(id: string, uid?: string): Promise<{ status: string }> {
  return request(`/analysis/${id}/dynamic`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid }),
  });
}

export async function cancelAnalysis(id: string): Promise<{ status: string }> {
  return request(`/analysis/${id}/cancel`, { method: 'POST' });
}

export async function getReport(id: string): Promise<{ format: string; content: string }> {
  return request(`/analysis/${id}/report`);
}

export async function getClustering(id: string): Promise<{ graph: unknown; correlations: unknown }> {
  return request(`/analysis/${id}/clustering`);
}

// ── Chat ──────────────────────────────────────────────────────────────────────

export async function chat(analysis_id: string, message: string, uid?: string): Promise<{ answer: string }> {
  return request('/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analysis_id, message, uid }),
  });
}

// ── SSE Stream (returns EventSource) ─────────────────────────────────────────

export function createAnalysisStream(id: string): EventSource {
  const token = typeof window !== 'undefined' ? localStorage.getItem('kavach_token') : '';
  return new EventSource(`${BASE}/analysis/${id}/stream?token=${token ?? ''}`);
}

// ── Sandbox Health ────────────────────────────────────────────────────────────

export async function getSandboxHealth(): Promise<Record<string, unknown>> {
  return request('/sandbox-health');
}
