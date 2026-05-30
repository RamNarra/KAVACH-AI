'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from 'firebase/auth';
import { ref, uploadBytesResumable, getDownloadURL } from 'firebase/storage';
import { collection, doc, onSnapshot, query, where, orderBy } from 'firebase/firestore';
import { auth, googleProvider, storage, db } from '../lib/firebase';
import { apiFetch, fetchSandboxHealth, downloadReport, sendChat } from '../lib/api';
import { DEMO_ANALYSIS } from '../lib/demo';
import type { AnalysisDoc, ThreatLevel } from '../lib/types';
import {
  DynamicAnalysisOperatorSmokeView,
  type AnalysisResultForUi,
} from '../lib/dynamic-analysis-ui';

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#81c995',
  LOW: '#81c995',
  MEDIUM: '#fdd663',
  HIGH: '#f28b82',
  CRITICAL: '#ea4335',
};


function activeStep(progress?: Record<string, string>) {
  if (!progress) return 'Starting';
  const running = Object.entries(progress).find(([, s]) => s === 'RUNNING');
  if (running) return running[0].replace(/_/g, ' ');
  return 'Finalizing';
}

function toDynamicUi(doc: AnalysisDoc): AnalysisResultForUi {
  return {
    id: doc.id,
    status: doc.status,
    evidence: doc.evidence as AnalysisResultForUi['evidence'],
  };
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [history, setHistory] = useState<AnalysisDoc[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [active, setActive] = useState<AnalysisDoc | null>(null);
  const [isDemo, setIsDemo] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploadPct, setUploadPct] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sandboxOk, setSandboxOk] = useState<boolean | null>(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatLog, setChatLog] = useState<{ role: 'user' | 'ai'; text: string }[]>([]);
  const [chatBusy, setChatBusy] = useState(false);

  useEffect(() => onAuthStateChanged(auth, (u) => { setUser(u); setAuthReady(true); }), []);

  useEffect(() => {
    fetchSandboxHealth().then((h) => setSandboxOk(h.sandbox_status === 'READY'));
  }, []);

  useEffect(() => {
    if (!user) return;
    const q = query(collection(db, 'apkanalysisresults'), where('uid', '==', user.uid), orderBy('created_at', 'desc'));
    return onSnapshot(q, (snap) => setHistory(snap.docs.map((d) => ({ id: d.id, ...d.data() } as AnalysisDoc))));
  }, [user]);

  useEffect(() => {
    if (isDemo) return;
    if (!activeId) return;
    return onSnapshot(doc(db, 'apkanalysisresults', activeId), (snap) => {
      if (snap.exists()) setActive({ id: snap.id, ...snap.data() } as AnalysisDoc);
    });
  }, [activeId, isDemo]);

  const signIn = async () => {
    try { await signInWithPopup(auth, googleProvider); }
    catch { setError('Sign-in failed.'); }
  };

  const analyze = async () => {
    if (!file || !user || busy) return;
    setError(null);
    setBusy(true);
    setUploadPct(0);
    setActiveId(null);
    setIsDemo(false);

    try {
      const storageRef = ref(storage, `apks/${user.uid}/${Date.now()}_${file.name}`);
      const url = await new Promise<string>((resolve, reject) => {
        uploadBytesResumable(storageRef, file).on(
          'state_changed',
          (s) => setUploadPct(Math.round((s.bytesTransferred / s.totalBytes) * 100)),
          reject,
          async () => resolve(await getDownloadURL(storageRef))
        );
      });
      const res = await apiFetch('/api/analyze?background=true', {
        method: 'POST',
        body: JSON.stringify({ apk_url: url, uid: user.uid, email: user.email }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Analysis failed to start.');
      setActiveId(data.id);
      setFile(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
      setUploadPct(0);
    }
  };

  const loadDemo = useCallback(() => {
    setIsDemo(true);
    setActiveId('demo');
    setActive(DEMO_ANALYSIS);
    setFile(null);
    setError(null);
  }, []);

  const reset = () => {
    setActiveId(null);
    setActive(null);
    setIsDemo(false);
    setFile(null);
    setChatLog([]);
    setChatOpen(false);
  };

  const current = isDemo ? active : activeId ? active : null;
  const displayHistory = user ? history : [];

  const view = useMemo(() => {
    if (!user) return 'auth';
    if (current?.status === 'PROCESSING' || busy) return 'scan';
    if (current?.status === 'COMPLETED' || current?.status === 'FAILED') return 'result';
    return 'home';
  }, [user, current, busy]);

  const score = current?.risk_score ?? 0;
  const level = (current?.threat_level ?? 'SAFE') as ThreatLevel;
  const accent = threatColor[level];
  const fraudScore = current?.banking_fraud?.fraud_score;

  const askChat = async () => {
    if (!chatInput.trim() || !current || chatBusy) return;
    const msg = chatInput.trim();
    setChatInput('');
    setChatLog((l) => [...l, { role: 'user', text: msg }]);
    setChatBusy(true);
    try {
      if (isDemo) {
        setChatLog((l) => [...l, { role: 'ai', text: 'Demo mode: this APK shows classic banking trojan lab patterns — SMS interception, overlay risk, and cleartext HTTP credential exfiltration.' }]);
      } else {
        const answer = await sendChat(current.id, msg);
        setChatLog((l) => [...l, { role: 'ai', text: answer }]);
      }
    } catch {
      setChatLog((l) => [...l, { role: 'ai', text: 'Could not reach analyst. Try again.' }]);
    } finally {
      setChatBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <header className="flex items-center justify-between px-6 py-5 max-w-3xl mx-auto w-full">
        <button type="button" onClick={reset} className="text-[15px] font-semibold tracking-tight bg-transparent border-0 cursor-pointer text-[var(--text)]">
          Kavach
        </button>
        <div className="flex items-center gap-4">
          {sandboxOk !== null && (
            <span className="flex items-center gap-1.5 text-[12px] text-[var(--muted)]" title="Sandbox status">
              <span className={`w-2 h-2 rounded-full ${sandboxOk ? 'bg-[var(--green)]' : 'bg-zinc-500'}`} />
              {sandboxOk ? 'Sandbox ready' : 'Sandbox offline'}
            </span>
          )}
          {user && (
            <button type="button" onClick={() => signOut(auth)} className="text-[13px] text-[var(--muted)] hover:text-[var(--text)] bg-transparent border-0 cursor-pointer">
              Sign out
            </button>
          )}
        </div>
      </header>

      <main className="flex-1 flex flex-col items-center px-6 pb-16 max-w-3xl mx-auto w-full">
        <AnimatePresence mode="wait">
          {view === 'auth' && authReady && (
            <motion.div key="auth" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="text-center space-y-8 w-full py-12">
              <div className="space-y-3">
                <h1 className="text-[40px] sm:text-[48px] font-semibold tracking-tight leading-[1.1]">Fraud APK analysis</h1>
                <p className="text-[17px] text-[var(--muted)] max-w-md mx-auto">AI-powered malware analysis for banking security teams.</p>
              </div>
              <button type="button" onClick={signIn} className="h-12 px-8 rounded-full bg-[var(--text)] text-[var(--bg)] text-[15px] font-medium border-0 cursor-pointer">
                Continue with Google
              </button>
            </motion.div>
          )}

          {view === 'home' && (
            <motion.div key="home" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full space-y-8 py-4">
              <div className="text-center space-y-2">
                <h1 className="text-[32px] font-semibold tracking-tight">Analyze an APK</h1>
                <p className="text-[15px] text-[var(--muted)]">Static + dynamic + banking fraud intelligence</p>
              </div>

              <label className="block cursor-pointer group">
                <input type="file" accept=".apk" className="sr-only" onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f?.name.endsWith('.apk')) { setFile(f); setError(null); }
                  else setError('APK only.');
                }} />
                <div className="rounded-3xl border border-dashed border-[var(--border)] bg-[var(--surface)] px-8 py-14 text-center group-hover:border-[rgba(138,180,248,0.4)] transition-colors">
                  <p className="text-[17px] font-medium">{file ? file.name : 'Select .apk'}</p>
                </div>
              </label>

              {error && <p className="text-[14px] text-[var(--red)] text-center">{error}</p>}

              {file && (
                <button type="button" onClick={analyze} disabled={busy} className="w-full h-12 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[15px] font-semibold border-0 cursor-pointer disabled:opacity-50">
                  Run analysis
                </button>
              )}

              <button type="button" onClick={loadDemo} className="w-full h-11 rounded-full border border-[var(--border)] bg-transparent text-[14px] text-[var(--muted)] cursor-pointer hover:text-[var(--text)]">
                View demo report
              </button>

              {displayHistory.length > 0 && (
                <ul className="space-y-1 pt-2">
                  {displayHistory.slice(0, 5).map((item) => (
                    <li key={item.id}>
                      <button type="button" onClick={() => { setIsDemo(false); setActiveId(item.id); }} className="w-full flex justify-between py-3 px-2 rounded-xl hover:bg-[var(--surface)] border-0 cursor-pointer text-left bg-transparent">
                        <span className="text-[15px] truncate">{item.filename || 'Unknown'}</span>
                        <span className="text-[13px] text-[var(--muted)] tabular-nums">{item.risk_score ?? '—'}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </motion.div>
          )}

          {view === 'scan' && (
            <motion.div key="scan" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center space-y-6 py-20 w-full">
              <p className="text-[20px] font-medium">{busy ? `Uploading ${uploadPct}%` : 'Analyzing'}</p>
              <p className="text-[15px] text-[var(--muted)] capitalize">{busy ? file?.name : activeStep(current?.progress)}</p>
            </motion.div>
          )}

          {view === 'result' && current && (
            <motion.div key="result" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full space-y-8 py-2">
              {current.status === 'FAILED' ? (
                <p className="text-center text-[var(--red)] text-[17px]">{current.error_message || 'Analysis failed.'}</p>
              ) : (
                <>
                  <div className="text-center space-y-2">
                    <p className="text-[80px] font-semibold tabular-nums leading-none" style={{ color: accent }}>{score}</p>
                    <p className="text-[13px] uppercase tracking-[0.15em] font-medium" style={{ color: accent }}>{level}</p>
                    {fraudScore != null && (
                      <p className="text-[14px] text-[var(--muted)]">Fraud score <span className="text-[var(--text)] tabular-nums">{fraudScore}</span></p>
                    )}
                    <p className="text-[14px] text-[var(--muted)]">{current.filename}</p>
                  </div>

                  {(current.investigation_report?.executive_verdict || current.investigation_report?.summary) && (
                    <div className="rounded-3xl bg-[var(--surface)] p-6">
                      <p className="text-[16px] leading-relaxed">{current.investigation_report.executive_verdict || current.investigation_report.summary}</p>
                    </div>
                  )}

                  {current.banking_fraud?.badges && current.banking_fraud.badges.length > 0 && (
                    <section className="space-y-3">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Banking fraud</p>
                      <div className="flex flex-wrap gap-2">
                        {current.banking_fraud.badges.map((b) => (
                          <span key={b.id} className="text-[12px] px-3 py-1.5 rounded-full bg-[var(--surface)] border border-[var(--border)]" title={b.summary}>
                            {b.title}
                          </span>
                        ))}
                      </div>
                    </section>
                  )}

                  {current.risk_decomposition?.components && (
                    <section className="rounded-3xl bg-[var(--surface)] p-6 space-y-4">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Risk breakdown</p>
                      <div className="space-y-3">
                        {Object.entries(current.risk_decomposition.components).map(([key, val]) => (
                          <div key={key}>
                            <div className="flex justify-between text-[13px] mb-1 capitalize">
                              <span className="text-[var(--muted)]">{key.replace('_', ' ')}</span>
                              <span className="tabular-nums">{val}</span>
                            </div>
                            <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                              <div className="h-full rounded-full bg-[var(--blue)]" style={{ width: `${Math.min(100, val)}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                      {current.risk_decomposition.summary && (
                        <p className="text-[13px] text-[var(--muted)]">{current.risk_decomposition.summary}</p>
                      )}
                    </section>
                  )}

                  {current.attack_techniques && current.attack_techniques.length > 0 && (
                    <section className="space-y-3">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">MITRE ATT&CK</p>
                      <div className="flex flex-wrap gap-2">
                        {current.attack_techniques.map((t) => (
                          <span key={t.id} className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-[var(--surface)] border border-[var(--border)]" title={t.name}>
                            {t.id}
                          </span>
                        ))}
                      </div>
                    </section>
                  )}

                  <FindingsBlock title="Threats" items={current.investigation_report?.suspicious_activities?.map((a) => ({ label: a.title, detail: a.description }))} />
                  <FindingsBlock title="Vulnerabilities" items={current.investigation_report?.code_vulnerabilities?.map((a) => ({ label: a.title, detail: a.description }))} />

                  {current.evidence?.dynamic_analysis && (
                    <section className="rounded-3xl bg-[var(--surface)] p-6">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-4">Runtime</p>
                      <DynamicAnalysisOperatorSmokeView activeResult={toDynamicUi(current)} />
                    </section>
                  )}

                  {(current.investigation_report?.recommendations?.length || current.banking_fraud?.recommended_actions?.length) ? (
                    <section className="rounded-3xl bg-[var(--surface)] p-6 space-y-3">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Actions</p>
                      <ul className="space-y-2">
                        {[...(current.investigation_report?.recommendations || []), ...(current.banking_fraud?.recommended_actions || [])].map((r, i) => (
                          <li key={i} className="text-[15px] pl-3 border-l-2 border-[var(--green)]">{r}</li>
                        ))}
                      </ul>
                    </section>
                  ) : null}

                  <div className="flex flex-wrap gap-3">
                    <button type="button" onClick={() => setChatOpen(!chatOpen)} className="flex-1 min-w-[120px] h-11 rounded-full border border-[var(--border)] bg-transparent text-[14px] cursor-pointer hover:bg-[var(--surface)]">
                      Ask AI
                    </button>
                    {!isDemo && (
                      <button type="button" onClick={() => downloadReport(current.id)} className="flex-1 min-w-[120px] h-11 rounded-full border border-[var(--border)] bg-transparent text-[14px] cursor-pointer hover:bg-[var(--surface)]">
                        Export report
                      </button>
                    )}
                  </div>

                  {chatOpen && (
                    <div className="rounded-3xl bg-[var(--surface)] p-4 space-y-3">
                      <div className="max-h-48 overflow-y-auto space-y-2 text-[14px]">
                        {chatLog.length === 0 && <p className="text-[var(--muted)]">Ask about fraud risk, remediation, or evidence.</p>}
                        {chatLog.map((m, i) => (
                          <p key={i} className={m.role === 'user' ? 'text-[var(--blue)]' : 'text-[var(--text)]'}>{m.text}</p>
                        ))}
                      </div>
                      <div className="flex gap-2">
                        <input
                          value={chatInput}
                          onChange={(e) => setChatInput(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && askChat()}
                          placeholder="Explain overlay risk to a branch manager…"
                          className="flex-1 h-10 px-4 rounded-full bg-[var(--surface-2)] border border-[var(--border)] text-[14px] text-[var(--text)] outline-none"
                        />
                        <button type="button" onClick={askChat} disabled={chatBusy} className="h-10 px-5 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[14px] font-medium border-0 cursor-pointer disabled:opacity-50">
                          Send
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )}

              <button type="button" onClick={reset} className="w-full h-12 rounded-full border border-[var(--border)] bg-transparent text-[15px] cursor-pointer hover:bg-[var(--surface)]">
                New analysis
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="py-5 text-center text-[11px] text-[var(--muted)]">IIT Hyderabad × Bank of India · APK deleted after analysis</footer>
    </div>
  );
}

function FindingsBlock({ title, items }: { title: string; items?: { label: string; detail?: string }[] }) {
  if (!items?.length) return null;
  return (
    <section className="rounded-3xl bg-[var(--surface)] overflow-hidden">
      <p className="px-6 pt-5 pb-2 text-[12px] uppercase tracking-widest text-[var(--muted)]">{title}</p>
      <ul>
        {items.map((item, i) => (
          <li key={i} className="px-6 py-4 border-t border-[var(--border)]">
            <p className="text-[15px] font-medium">{item.label}</p>
            {item.detail && <p className="text-[14px] text-[var(--muted)] mt-1 line-clamp-2">{item.detail}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}
