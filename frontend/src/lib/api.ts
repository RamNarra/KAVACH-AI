import { auth } from './firebase';

const API = (process.env.NEXT_PUBLIC_API_BASE_URL || '').replace(/\/$/, '');

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json');
  }
  const user = auth.currentUser;
  if (user) {
    const token = await user.getIdToken();
    headers.set('Authorization', `Bearer ${token}`);
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

export async function triggerDynamicAnalysis(analysisId: string, uid: string): Promise<any> {
  const res = await apiFetch(`/api/analysis/${analysisId}/dynamic`, {
    method: 'POST',
    body: JSON.stringify({ uid }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Dynamic analysis failed to start.');
  return data;
}
