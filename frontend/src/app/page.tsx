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
import { apiFetch, fetchSandboxHealth, downloadReport, sendChat, triggerDynamicAnalysis } from '../lib/api';
import { DEMO_ANALYSIS } from '../lib/demo';
import type { AnalysisDoc, ThreatLevel } from '../lib/types';
import {
  DynamicAnalysisOperatorSmokeView,
  type AnalysisResultForUi,
} from '../lib/dynamic-analysis-ui';
import { livelyScanHeadline, recentScanLogs, runningStepKeys } from '../lib/scan-messages';
import { ChatBubble, MarkdownBody } from '../lib/chat-ui';

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#81c995',
  LOW: '#81c995',
  MEDIUM: '#fdd663',
  HIGH: '#f28b82',
  CRITICAL: '#ea4335',
};


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
  const [scanTick, setScanTick] = useState(0);
  const [summaryExpanded, setSummaryExpanded] = useState(false);

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

  const startDynamic = async () => {
    if (!current || !user || busy) return;
    setError(null);
    setBusy(true);
    try {
      await triggerDynamicAnalysis(current.id, user.uid);
      setActiveId(current.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start dynamic analysis.');
    } finally {
      setBusy(false);
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

  useEffect(() => {
    if (view !== 'scan') return;
    const health = setInterval(() => {
      fetchSandboxHealth().then((h) => setSandboxOk(h.sandbox_status === 'READY'));
    }, 5000);
    const tick = setInterval(() => setScanTick((t) => t + 1), 2400);
    return () => {
      clearInterval(health);
      clearInterval(tick);
    };
  }, [view]);

  const scanHeadline = livelyScanHeadline(current?.progress, current?.logs, scanTick);
  const scanFeed = recentScanLogs(current?.logs, 8);
  const parallelSteps = runningStepKeys(current?.progress);

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
            <motion.div key="scan" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-center space-y-8 py-16 w-full max-w-lg mx-auto">
              <div className="space-y-3">
                <p className="text-[20px] font-medium">{busy ? `Uploading ${uploadPct}%` : 'Analyzing'}</p>
                <AnimatePresence mode="wait">
                  <motion.p
                    key={busy ? `upload-${uploadPct}` : scanHeadline}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.25 }}
                    className="text-[15px] text-[var(--muted)] leading-relaxed min-h-[48px]"
                  >
                    {busy ? `Securely uploading ${file?.name ?? 'APK'}…` : scanHeadline}
                  </motion.p>
                </AnimatePresence>
              </div>

              {!busy && parallelSteps.length > 0 && (
                <div className="flex flex-wrap justify-center gap-2">
                  {parallelSteps.map((step) => (
                    <span
                      key={step}
                      className="text-[11px] px-3 py-1 rounded-full border border-[var(--blue)]/30 bg-[var(--blue)]/10 text-[var(--blue)] animate-pulse"
                    >
                      {step.replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              )}

              {!busy && (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-4 py-3 text-left space-y-2 min-h-[140px]">
                  <p className="text-[11px] uppercase tracking-widest text-[var(--muted)]">Live trace</p>
                  {scanFeed.length === 0 ? (
                    <p className="text-[13px] text-[var(--muted)] animate-pulse">Spinning up decompilers and sandbox hooks…</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {scanFeed.map((line, i) => (
                        <motion.li
                          key={`${i}-${line.slice(0, 24)}`}
                          initial={{ opacity: 0, x: -4 }}
                          animate={{ opacity: 1, x: 0 }}
                          className={`text-[13px] leading-snug ${i === scanFeed.length - 1 ? 'text-[var(--text)]' : 'text-[var(--muted)]'}`}
                        >
                          {line}
                        </motion.li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              <div className="flex justify-center gap-1.5 pt-2">
                {[0, 1, 2].map((i) => (
                  <span
                    key={i}
                    className="w-1.5 h-1.5 rounded-full bg-[var(--blue)] animate-pulse"
                    style={{ animationDelay: `${i * 180}ms` }}
                  />
                ))}
              </div>
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

                  {(current.investigation_report?.summary || current.investigation_report?.executive_verdict) && (() => {
                    const summaryText = current.investigation_report?.summary || current.investigation_report?.executive_verdict || '';
                    return (
                      <div className="rounded-3xl bg-[var(--surface)] p-6 space-y-3">
                        <div className={summaryExpanded ? '' : 'line-clamp-[8] overflow-hidden'}>
                          <MarkdownBody text={summaryText} />
                        </div>
                        <button
                          type="button"
                          onClick={() => setSummaryExpanded(e => !e)}
                          className="text-[13px] text-[var(--blue)] bg-transparent border-0 cursor-pointer p-0 hover:opacity-80"
                        >
                          {summaryExpanded ? 'Show less ↑' : 'Show more ↓'}
                        </button>
                      </div>
                    );
                  })()}

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
                              <span className="tabular-nums">{String(val)}</span>
                            </div>
                            <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                              <div className="h-full rounded-full bg-[var(--blue)]" style={{ width: `${Math.min(100, Number(val) || 0)}%` }} />
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
                      <div className="space-y-2">
                        {current.attack_techniques.map((t) => (
                          <div key={t.id} className="rounded-2xl bg-[var(--surface)] border border-[var(--border)] p-4 space-y-1.5">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20">{t.id}</span>
                                <span className="text-[14px] font-semibold">{t.name}</span>
                              </div>
                              {t.tactic && (
                                <span className="text-[11px] px-2 py-0.5 rounded-full bg-[var(--surface-2)] text-[var(--muted)] whitespace-nowrap border border-[var(--border)] shrink-0">{t.tactic}</span>
                              )}
                            </div>
                            {t.sources && t.sources.length > 0 && (
                              <ul className="space-y-1 pt-1">
                                {t.sources.map((s, si) => (
                                  <li key={si} className="text-[13px] text-[var(--muted)] pl-3 border-l border-[var(--border)]">
                                    <span className="text-[var(--text)] font-medium">{String(s.source || '')}</span>{s.detail ? ` — ${String(s.detail)}` : ''}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        ))}
                      </div>
                    </section>
                  )}

                  <FindingsBlock title="Threats" items={current.investigation_report?.suspicious_activities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity }))} />
                  <FindingsBlock title="Vulnerabilities" items={current.investigation_report?.code_vulnerabilities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity }))} />

                  {(!current.evidence?.dynamic_analysis || current.progress?.dynamic_sandbox === "SKIPPED") ? (
                    <section className="rounded-3xl bg-[var(--surface)] p-6 border border-[var(--border)] space-y-4">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Runtime Analysis</p>
                      <div className="space-y-2">
                        <p className="text-[15px] font-medium">Interactive Dynamic Sandbox</p>
                        {score < 30 ? (
                          <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                            No critical static threats were found. However, malware can dynamically load encrypted payloads or check for VM signatures. Booting the dynamic emulator allows Kavach to trace runtime API calls, network sockets, and crypt operations.
                          </p>
                        ) : (
                          <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                            Static warnings were detected in the codebase. Initiate dynamic trace monitoring to inspect active network packets, dynamic overlays, or evasion techniques at runtime.
                          </p>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={startDynamic}
                        disabled={busy}
                        className="w-full h-11 rounded-full bg-[var(--blue)] text-white text-[14px] font-semibold cursor-pointer hover:opacity-90 disabled:opacity-50 transition-opacity flex items-center justify-center gap-2"
                      >
                        <span className="text-[16px]">⚡</span> Initiate Dynamic Sandbox Analysis
                      </button>
                    </section>
                  ) : (
                    <section className="rounded-3xl bg-[var(--surface)] p-6">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-4">Runtime</p>
                      <DynamicAnalysisOperatorSmokeView activeResult={toDynamicUi(current)} />
                    </section>
                  )}

                  {(current.investigation_report?.recommendations?.length || current.banking_fraud?.recommended_actions?.length) ? (
                    <section className="rounded-3xl bg-[var(--surface)] p-6 space-y-3">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Remediation Tips</p>
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
                    <div className="rounded-3xl bg-[var(--surface)] p-4 space-y-4">
                      <div className="max-h-[min(420px,50vh)] overflow-y-auto space-y-4 pr-1">
                        {chatLog.length === 0 && (
                          <p className="text-[14px] text-[var(--muted)] text-center py-6">
                            Ask about fraud risk, remediation, or evidence — powered by Gemini.
                          </p>
                        )}
                        {chatLog.map((m, i) => (
                          <ChatBubble key={i} role={m.role} text={m.text} />
                        ))}
                        {chatBusy && (
                          <div className="flex gap-3 items-center text-[13px] text-[var(--muted)]">
                            <span className="w-8 h-8 rounded-full bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center animate-pulse">✦</span>
                            Gemini is thinking…
                          </div>
                        )}
                      </div>
                      <div className="flex gap-2">
                        <input
                          value={chatInput}
                          onChange={(e) => setChatInput(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && askChat()}
                          placeholder="Explain overlay risk to a branch manager…"
                          className="flex-1 h-11 px-4 rounded-full bg-[var(--surface-2)] border border-[var(--border)] text-[14px] text-[var(--text)] outline-none focus:border-[var(--blue)]/50"
                        />
                        <button type="button" onClick={askChat} disabled={chatBusy} className="h-11 px-5 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[14px] font-medium border-0 cursor-pointer disabled:opacity-50">
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

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-[#ea4335]/10', text: 'text-[#ea4335]', border: 'border-l-[#ea4335]' },
  HIGH:     { bg: 'bg-[#f28b82]/10', text: 'text-[#f28b82]', border: 'border-l-[#f28b82]' },
  MEDIUM:   { bg: 'bg-[#fdd663]/10', text: 'text-[#fdd663]', border: 'border-l-[#fdd663]' },
  LOW:      { bg: 'bg-[#81c995]/10', text: 'text-[#81c995]', border: 'border-l-[#81c995]' },
};

function FindingsBlock({ title, items }: { title: string; items?: { label: string; detail?: string; severity?: string }[] }) {
  if (!items?.length) return null;
  return (
    <section className="rounded-3xl bg-[var(--surface)] overflow-hidden">
      <p className="px-6 pt-5 pb-3 text-[12px] uppercase tracking-widest text-[var(--muted)]">{title}</p>
      <ul>
        {items.map((item, i) => {
          const sev = (item.severity || '').toUpperCase();
          const colors = SEVERITY_COLORS[sev] || { bg: '', text: 'text-[var(--muted)]', border: 'border-l-[var(--border)]' };
          return (
            <li key={i} className={`px-6 py-4 border-t border-[var(--border)] border-l-4 ${colors.border}`}>
              <div className="flex items-start justify-between gap-3 mb-1">
                <p className="text-[15px] font-semibold leading-snug">{String(item.label || '')}</p>
                {sev && SEVERITY_COLORS[sev] && (
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 ${colors.bg} ${colors.text}`}>{sev}</span>
                )}
              </div>
              {item.detail && (
                <p className="text-[13px] text-[var(--muted)] leading-relaxed">{String(item.detail)}</p>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
