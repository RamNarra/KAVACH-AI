'use client';

import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from 'firebase/auth';
import { collection, doc, onSnapshot, query, where, orderBy } from 'firebase/firestore';
import { auth, googleProvider, db } from '../lib/firebase';
import { apiFetch, fetchSandboxHealth, downloadReport, sendChat, triggerDynamicAnalysis, isLocalAPI, uploadApkDirect } from '../lib/api';
import { DEMO_ANALYSIS } from '../lib/demo';
import type { AnalysisDoc, ThreatLevel } from '../lib/types';
import {
  DynamicAnalysisOperatorSmokeView,
  type AnalysisResultForUi,
} from '../lib/dynamic-analysis-ui';
import { livelyScanHeadline, recentScanLogs, runningStepKeys } from '../lib/scan-messages';
import { ChatBubble, MarkdownBody } from '../lib/chat-ui';

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#10b981',
  LOW: '#10b981',
  MEDIUM: '#f97316',
  HIGH: '#f43f5e',
  CRITICAL: '#f43f5e',
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
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sandboxOk, setSandboxOk] = useState<boolean | null>(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatLog, setChatLog] = useState<{ role: 'user' | 'ai'; text: string }[]>([]);
  const [chatBusy, setChatBusy] = useState(false);
  const [scanTick, setScanTick] = useState(0);
  const [summaryExpanded, setSummaryExpanded] = useState(false);
  const [mitreExpanded, setMitreExpanded] = useState(false);
  const [expandedTechniques, setExpandedTechniques] = useState<Record<string, boolean>>({});
  const [staticTab, setStaticTab] = useState<'manifest' | 'apkid' | 'quark' | 'androguard' | 'secrets' | 'network' | 'compliance'>('manifest');
  const [storyTab, setStoryTab] = useState<'static' | 'dynamic' | 'final'>('static');
  const [estSecondsRemaining, setEstSecondsRemaining] = useState(30);

  useEffect(() => {
    return onAuthStateChanged(auth, (u) => {
      setUser(u);
      setAuthReady(true);
    });
  }, []);

  useEffect(() => {
    fetchSandboxHealth().then((h) => setSandboxOk(h.sandbox_status === 'READY'));
  }, []);

  useEffect(() => {
    if (!user) return;
    const q = query(collection(db, 'apkanalysisresults'), where('uid', '==', user.uid), orderBy('created_at', 'desc'));
    return onSnapshot(q, (snap) => setHistory(snap.docs.map((d) => ({ id: d.id, ...d.data() } as AnalysisDoc))));
  }, [user]);

  useEffect(() => {
    setSummaryExpanded(false);
    setMitreExpanded(false);
    if (active?.evidence?.dynamic_analysis?.status === 'COMPLETED') {
      setStoryTab('final');
    } else {
      setStoryTab('static');
    }
  }, [activeId, active?.evidence?.dynamic_analysis?.status]);

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
    setUploading(true);
    setUploadPct(0);
    setActiveId(null);
    setIsDemo(false);

    const initialSeconds = Math.min(75, Math.max(25, Math.round(file.size / (1024 * 1024) * 0.6) + 20));
    setEstSecondsRemaining(initialSeconds);

    try {
      // Direct file upload endpoint bypasses Firebase Storage for high-speed, robust uploads in both local and production environments
      const data = await uploadApkDirect(file, user.email, user.uid, setUploadPct);
      setUploading(false);
      setActiveId(data.id);
      setFile(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
      setUploading(false);
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
      setStoryTab('dynamic');
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
    if (current?.status === 'PROCESSING') {
      if (current?.progress?.dynamic_sandbox === 'RUNNING') {
        return 'result'; // Keep user on results dashboard during dynamic sandbox executions
      }
      return 'scan'; // Show scanner loader only for initial static decompiler runs
    }
    if (busy || uploading) return 'scan';
    if (current?.status === 'COMPLETED' || current?.status === 'FAILED') return 'result';
    return 'home';
  }, [user, current, busy, uploading]);

  const scanHeadline = livelyScanHeadline(current?.progress, current?.logs, scanTick);
  const scanFeed = recentScanLogs(current?.logs, 8);
  const parallelSteps = runningStepKeys(current?.progress);

  const progressPercent = useMemo(() => {
    if (uploading) {
      return Math.min(15, Math.round(uploadPct * 0.15));
    }
    if (!current?.progress) return 15;
    
    const stepKeys = ['download', 'apktool', 'jadx', 'apkid', 'quark', 'net_sec', 'androguard', 'secrets', 'semgrep', 'trufflehog', 'gemini', 'finalize'];
    const completedCount = stepKeys.filter(k => current.progress?.[k] === 'COMPLETED').length;
    
    // Completed count ranges from 0 to 12. Let's map it from 15% to 95%
    const staticPercent = 15 + Math.round((completedCount / stepKeys.length) * 80);
    return Math.min(95, staticPercent);
  }, [uploading, uploadPct, current?.progress]);

  const baseEstimate = useMemo(() => {
    if (uploading) {
      return Math.round((100 - uploadPct) * 0.15) + 35;
    }
    if (!current?.progress) return 35;
    
    const stepDurations: Record<string, number> = {
      download: 2,
      apktool: 4,
      jadx: file ? Math.round(file.size / (1024 * 1024) * 0.7) + 12 : 20,
      apkid: 2,
      quark: 5,
      net_sec: 2,
      androguard: 2,
      secrets: 6,
      semgrep: 6,
      trufflehog: 6,
      gemini: 8,
      finalize: 2,
    };
    
    const stepKeys = ['download', 'apktool', 'jadx', 'apkid', 'quark', 'net_sec', 'androguard', 'secrets', 'semgrep', 'trufflehog', 'gemini', 'finalize'];
    
    let activeIndex = stepKeys.findIndex(k => current.progress?.[k] === 'RUNNING');
    if (activeIndex === -1) {
      activeIndex = stepKeys.findIndex(k => current.progress?.[k] !== 'COMPLETED');
    }
    if (activeIndex === -1) return 2;
    
    let remaining = 0;
    for (let i = activeIndex; i < stepKeys.length; i++) {
      const key = stepKeys[i];
      remaining += stepDurations[key] ?? 3;
    }
    return Math.max(3, remaining);
  }, [uploading, uploadPct, current?.progress, file]);

  // Sync state with baseEstimate when baseEstimate decreases or jumps
  useEffect(() => {
    setEstSecondsRemaining((prev) => {
      if (baseEstimate < prev || Math.abs(baseEstimate - prev) > 8) {
        return baseEstimate;
      }
      return prev;
    });
  }, [baseEstimate]);

  useEffect(() => {
    if (view !== 'scan') return;
    const health = setInterval(() => {
      fetchSandboxHealth().then((h) => setSandboxOk(h.sandbox_status === 'READY'));
    }, 5000);
    const tick = setInterval(() => setScanTick((t) => t + 1), 2400);
    
    const countdown = setInterval(() => {
      setEstSecondsRemaining((prev) => {
        if (prev > 2) {
          return prev - 1;
        }
        return 2;
      });
    }, 1000);
    
    return () => {
      clearInterval(health);
      clearInterval(tick);
      clearInterval(countdown);
    };
  }, [view]);

  const hasDynamic = useMemo(() => {
    return Boolean(current?.evidence?.dynamic_analysis && current?.progress?.dynamic_sandbox !== 'SKIPPED');
  }, [current]);

  const activeScore = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.risk_score ?? (hasDynamic ? 0 : current?.risk_score) ?? 0;
    }
    return current?.risk_score ?? 0;
  }, [storyTab, current, hasDynamic]);

  const activeAbsoluteScore = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.absolute_threat_score ?? current?.absolute_threat_score;
    }
    return current?.absolute_threat_score ?? current?.static_analysis?.absolute_threat_score;
  }, [storyTab, current]);

  const activeLevel = useMemo(() => {
    if (storyTab === 'static') {
      return (current?.static_analysis?.threat_level ?? (hasDynamic ? 'SAFE' : current?.threat_level) ?? 'SAFE') as ThreatLevel;
    }
    return (current?.threat_level ?? 'SAFE') as ThreatLevel;
  }, [storyTab, current, hasDynamic]);

  const activeAccent = threatColor[activeLevel];

  const activeFraudScore = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.banking_fraud?.fraud_score ?? (hasDynamic ? undefined : current?.banking_fraud?.fraud_score);
    }
    return current?.banking_fraud?.fraud_score;
  }, [storyTab, current, hasDynamic]);

  const activeSummaryText = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.investigation_report?.summary ?? (hasDynamic ? '' : current?.investigation_report?.summary ?? current?.investigation_report?.executive_verdict) ?? '';
    }
    if (storyTab === 'dynamic') {
      return current?.investigation_report?.dynamic_summary ?? current?.investigation_report?.summary ?? '';
    }
    return current?.investigation_report?.final_report ?? current?.investigation_report?.summary ?? '';
  }, [storyTab, current, hasDynamic]);

  const activeInterpret = useMemo(() => {
    const report = storyTab === 'static' ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report)) : current?.investigation_report;
    return report?.runtime_findings_interpretation || 'E2E scan complete.';
  }, [storyTab, current, hasDynamic]);

  const activeLimit = useMemo(() => {
    const report = storyTab === 'static' ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report)) : current?.investigation_report;
    return report?.analysis_limitations || 'None.';
  }, [storyTab, current, hasDynamic]);

  const activeBadges = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.banking_fraud?.badges ?? (hasDynamic ? [] : current?.banking_fraud?.badges) ?? [];
    }
    return current?.banking_fraud?.badges ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeRiskDecomposition = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.risk_decomposition ?? (hasDynamic ? undefined : current?.risk_decomposition);
    }
    return current?.risk_decomposition;
  }, [storyTab, current, hasDynamic]);

  const activeAttackTechniques = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.attack_techniques ?? (hasDynamic ? [] : current?.attack_techniques) ?? [];
    }
    return current?.attack_techniques ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeThreats = useMemo(() => {
    const report = storyTab === 'static' ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report)) : current?.investigation_report;
    return report?.suspicious_activities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity })) ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeVulnerabilities = useMemo(() => {
    const report = storyTab === 'static' ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report)) : current?.investigation_report;
    return report?.code_vulnerabilities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity })) ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeRemediation = useMemo(() => {
    const report = storyTab === 'static' ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report)) : current?.investigation_report;
    const fraud = storyTab === 'static' ? (current?.static_analysis?.banking_fraud ?? (hasDynamic ? undefined : current?.banking_fraud)) : current?.banking_fraud;
    return [...(report?.recommendations || []), ...(fraud?.recommended_actions || [])];
  }, [storyTab, current, hasDynamic]);

  const score = activeScore;
  const level = activeLevel;
  const accent = activeAccent;
  const fraudScore = activeFraudScore;
  const absoluteScore = activeAbsoluteScore;

  const askChat = async (overrideMsg?: string) => {
    const rawInput = overrideMsg || chatInput;
    if (!rawInput.trim() || !current || chatBusy) return;
    const msg = rawInput.trim();
    if (!overrideMsg) setChatInput('');
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
      <header className={`flex items-center justify-between px-6 py-5 mx-auto w-full transition-all duration-500 ${view === 'result' ? 'max-w-7xl' : 'max-w-3xl'}`}>
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
            <div className="flex items-center gap-3">
              <span className="text-[13px] text-[var(--muted)] select-none">
                {user.displayName || user.email}
              </span>
              <button type="button" onClick={() => signOut(auth)} className="text-[13px] text-[var(--muted)] hover:text-[var(--text)] bg-transparent border-0 cursor-pointer">
                Sign out
              </button>
            </div>
          )}
        </div>
      </header>

      <main className={`flex-1 flex flex-col items-center px-6 pb-16 mx-auto w-full transition-all duration-500 ${view === 'result' ? 'max-w-7xl' : 'max-w-3xl'}`}>
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
                <h1 className="text-[36px] font-bold tracking-tight bg-gradient-to-r from-zinc-100 to-zinc-400 bg-clip-text text-transparent">Analyze target APK</h1>
                <p className="text-[15px] text-[var(--muted)]">Initiate sandbox, manifest, and deep static auditing.</p>
              </div>

              <label className="block cursor-pointer group">
                <input type="file" accept=".apk" className="sr-only" onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f?.name.endsWith('.apk')) { setFile(f); setError(null); }
                  else setError('APK files only.');
                }} />
                
                {!file ? (
                  <div className="rounded-3xl border border-dashed border-[var(--border)] bg-zinc-950/20 px-8 py-16 text-center group-hover:border-[var(--blue-glow)] hover:bg-zinc-950/30 transition-all duration-300 flex flex-col items-center justify-center space-y-5 relative overflow-hidden">
                    <div className="relative flex items-center justify-center w-16 h-16 rounded-full bg-zinc-900 border border-[var(--border)] group-hover:border-[var(--blue)]/30 transition-all duration-300">
                      <div className="absolute inset-0 rounded-full border border-[var(--blue)]/10 animate-ping opacity-30 pointer-events-none" />
                      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-7 h-7 text-[var(--muted)] group-hover:text-[var(--blue)] transition-colors">
                        <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
                        <path d="M12 12v9" />
                        <path d="m16 16-4-4-4 4" />
                      </svg>
                    </div>
                    <div className="space-y-1">
                      <p className="text-[17px] font-semibold text-zinc-100 group-hover:text-[var(--blue)] transition-colors">Select target APK file</p>
                      <p className="text-[13px] text-[var(--muted)] max-w-sm leading-relaxed">Drag and drop your file here, or click to browse local files for static & dynamic evaluation.</p>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-3xl border border-[var(--blue)]/30 bg-zinc-950/45 px-8 py-10 text-center flex flex-col items-center justify-center space-y-4 transition-all duration-300 relative overflow-hidden">
                    <div className="laser-scanner" />
                    <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-[var(--blue)]/10 border border-[var(--blue)]/20 text-[var(--blue)]">
                      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    </div>
                    <div className="space-y-1">
                      <p className="text-[17px] font-semibold text-zinc-100">{file.name}</p>
                      <p className="text-[13px] text-[var(--muted)]">Size: {file.size > 1024 * 1024 ? `${(file.size / (1024 * 1024)).toFixed(2)} MB` : `${(file.size / 1024).toFixed(1)} KB`} | Format: Android Application</p>
                    </div>
                  </div>
                )}
              </label>

              {error && <p className="text-[14px] text-[var(--red)] text-center font-medium">{error}</p>}

              {file && (
                <button type="button" onClick={analyze} disabled={busy} className="w-full h-12 rounded-full bg-[var(--blue)] text-[#030305] text-[15px] font-bold border-0 cursor-pointer disabled:opacity-50 hover:bg-[#5ca2ff] transition-all duration-300 hover:shadow-[0_0_20px_rgba(77,144,254,0.35)] flex items-center justify-center gap-1.5">
                  Initiate Security Analysis
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M5 12h14" />
                    <path d="m12 5 7 7-7 7" />
                  </svg>
                </button>
              )}

              <button type="button" onClick={loadDemo} className="w-full h-11 rounded-full border border-[var(--border)] bg-transparent text-[14px] text-[var(--muted)] font-medium cursor-pointer hover:text-[var(--text)] hover:bg-zinc-900/30 transition-all duration-300">
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
                <p className="text-[20px] font-medium">{uploading ? `Uploading ${uploadPct}%` : 'Analyzing'}</p>
                <AnimatePresence mode="wait">
                  <motion.p
                    key={uploading ? `upload-${uploadPct}` : scanHeadline}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.25 }}
                    className="text-[15px] text-[var(--muted)] leading-relaxed min-h-[48px]"
                  >
                    {uploading ? `Securely uploading ${file?.name ?? 'APK'}…` : scanHeadline}
                  </motion.p>
                </AnimatePresence>
              </div>

              {/* Premium Neon Progress Bar & Time Estimate */}
              <div className="space-y-2.5 px-4 pt-2">
                <div className="flex justify-between items-center text-[12.5px] font-semibold text-[var(--muted)]">
                  <span>Progress Status</span>
                  <span className="tabular-nums text-[var(--blue)] font-bold drop-shadow-[0_0_8px_rgba(59,130,246,0.4)]">{progressPercent}% Completed</span>
                </div>
                <div className="h-2.5 w-full rounded-full bg-zinc-950/60 border border-[var(--border)] overflow-hidden p-0.5 relative">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-[var(--blue)]/70 to-[var(--blue)] shadow-[0_0_12px_var(--blue)]"
                    initial={{ width: '0%' }}
                    animate={{ width: `${progressPercent}%` }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                  />
                </div>
                <div className="flex justify-between items-center text-[11.5px] text-[var(--muted)]/80">
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--blue)] animate-ping" />
                    Forensic engines active
                  </span>
                  <span className="tabular-nums font-medium text-zinc-300">
                    Est. time remaining: <strong className="text-[var(--blue)]">{estSecondsRemaining}s</strong>
                  </span>
                </div>
              </div>

              {parallelSteps.length > 0 && (
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

              <div className="relative rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-4 py-3 text-left space-y-2 min-h-[140px] overflow-hidden">
                <div className="laser-scanner" />
                <p className="text-[11px] uppercase tracking-widest text-[var(--muted)] z-10 relative">Live trace</p>
                {scanFeed.length === 0 ? (
                  <p className="text-[13px] text-[var(--muted)] animate-pulse z-10 relative">Spinning up decompilers and sandbox hooks…</p>
                ) : (
                  <ul className="space-y-1.5 z-10 relative">
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
            <motion.div key="result" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full py-2">
              {current.status === 'FAILED' ? (
                <p className="text-center text-[var(--red)] text-[17px]">{current.error_message || 'Analysis failed.'}</p>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start w-full">
                  {/* COLUMN 1: Threat Score & Overview (lg:col-span-4) */}
                  <div className={`space-y-6 lg:sticky lg:top-6 transition-all duration-500 ${chatOpen ? 'lg:col-span-3' : 'lg:col-span-4'}`}>

                    <div className="security-card p-6 flex flex-col items-center text-center space-y-6 relative overflow-hidden">
                      {/* SVG Gauge */}
                      <div className="relative flex items-center justify-center w-40 h-40 mx-auto">
                        <div 
                          className="absolute inset-0 rounded-full opacity-10 transition-all duration-500" 
                          style={{ 
                            background: accent,
                            filter: 'blur(20px)'
                          }} 
                        />
                        <svg className="w-full h-full transform -rotate-90">
                          <defs>
                            <filter id="cyber-neon-glow" x="-20%" y="-20%" width="140%" height="140%">
                              <feGaussianBlur stdDeviation="4" result="blur" />
                              <feMerge>
                                <feMergeNode in="blur" />
                                <feMergeNode in="SourceGraphic" />
                              </feMerge>
                            </filter>
                          </defs>
                          <circle
                            cx="80"
                            cy="80"
                            r="68"
                            fill="transparent"
                            stroke="rgba(255, 255, 255, 0.03)"
                            strokeWidth="8"
                          />
                          <circle
                            cx="80"
                            cy="80"
                            r="68"
                            fill="transparent"
                            stroke={accent}
                            strokeWidth="8"
                            strokeDasharray={String(2 * Math.PI * 68)}
                            strokeDashoffset={String(2 * Math.PI * 68 * (1 - score / 100))}
                            strokeLinecap="round"
                            filter="url(#cyber-neon-glow)"
                            className="transition-all duration-1000 ease-out"
                            style={{ filter: `drop-shadow(0 0 6px ${accent})` }}
                          />
                        </svg>
                        <div className="absolute flex flex-col items-center justify-center text-center">
                          <span className="text-[44px] font-bold tracking-tight tabular-nums leading-none" style={{ color: accent }}>{score}</span>
                          <span className="text-[10px] tracking-[0.12em] font-bold uppercase mt-1 opacity-80" style={{ color: accent }}>{level}</span>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <p className="text-[13px] text-[var(--muted)] font-medium">Threat Score</p>
                          <p className="text-[12px] text-[var(--muted)]/75">Combined static and dynamic threat level.</p>
                        </div>
                        {absoluteScore !== undefined && (
                          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-zinc-950 border border-[var(--border)] text-[12px] font-semibold text-zinc-300">
                            <span className="w-2.5 h-2.5 rounded-full bg-[var(--red)] animate-pulse" />
                            Threat Severity Index: <span className="text-[var(--red)] tabular-nums">{absoluteScore} pts</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {fraudScore != null && (
                      <div className="security-card p-5 flex items-center justify-between">
                        <div className="flex flex-col pr-3">
                          <span className="text-[12px] text-[var(--muted)] font-bold uppercase tracking-wider">Fraud Score</span>
                          <span className="text-[12px] text-[var(--muted)]/80 mt-1">Overlay & SMS intercept indicators.</span>
                        </div>
                        <div className="relative group/fraud shrink-0 flex items-center justify-center w-12 h-12 rounded-2xl bg-zinc-900/50 border border-[var(--border)]">
                          <span className="text-[17px] font-bold tabular-nums" style={{ color: accent }}>
                            {fraudScore}
                          </span>
                          <div className="absolute right-0 bottom-full mb-2 w-64 p-3 bg-zinc-950/95 text-[11px] text-zinc-300 rounded-xl shadow-xl border border-zinc-800 hidden group-hover/fraud:block z-50 text-center leading-relaxed font-normal normal-case pointer-events-none">
                            <strong>Fraud Index (0-100)</strong>
                            <p className="mt-1">Likelihood of overlays, SMS interception, and contact theft targeting banking users.</p>
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="security-card p-5 space-y-3">
                      <div className="flex items-center justify-between border-b border-[var(--border)] pb-2">
                        <span className="text-[12px] uppercase tracking-wider font-semibold text-[var(--muted)]">Metadata</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--muted)] border border-[var(--border)]">APK</span>
                      </div>
                      <p className="text-[14px] font-medium break-all text-[var(--text)]">{current.filename}</p>
                      {activeBadges.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {activeBadges.map((b) => (
                            <span key={b.id} className="text-[11px] px-2.5 py-1 rounded-full bg-[var(--surface-2)] border border-[var(--border)] text-[var(--muted)]" title={b.summary}>
                              {b.title}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Live Telemetry Log stream inside Column 1 */}
                    <div className="security-card p-5 space-y-2.5">
                      <div className="flex items-center justify-between border-b border-[var(--border)] pb-2">
                        <span className="text-[11px] uppercase tracking-widest text-[var(--muted)] font-semibold">Logs Trace</span>
                        <span className="w-1.5 h-1.5 rounded-full bg-[var(--green)] animate-pulse" />
                      </div>
                      <div className="h-32 overflow-y-auto font-mono text-[11px] text-[var(--muted)] space-y-1.5 pr-1 select-none scrollbar-thin">
                        {current.logs && current.logs.length > 0 ? (
                          current.logs.slice(-10).map((log, i) => (
                            <p key={i} className="break-all leading-tight opacity-75">
                              <span className="text-[var(--blue)] mr-1">$</span>
                              {log}
                            </p>
                          ))
                        ) : (
                          <p className="opacity-50 italic">Logs trace complete.</p>
                        )}
                      </div>
                    </div>

                    {/* Primary Action Controls */}
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => setChatOpen(!chatOpen)}
                        className={`flex-1 h-12 rounded-full border text-[13px] font-semibold cursor-pointer transition-all duration-300 flex items-center justify-center gap-1.5 ${
                          chatOpen
                            ? 'bg-[var(--blue)]/15 border-[var(--blue)]/40 text-[var(--blue)]'
                            : 'bg-transparent border-[var(--border)] text-[var(--text)] hover:bg-[var(--surface-2)]'
                        }`}
                      >
                        💬 Ask AI
                      </button>
                      {!isDemo && (
                        <button
                          type="button"
                          onClick={() => downloadReport(current.id)}
                          className="flex-1 h-12 rounded-full border border-[var(--border)] bg-transparent text-[13px] font-semibold cursor-pointer hover:bg-[var(--surface-2)] transition-all flex items-center justify-center gap-1.5"
                        >
                          📥 Export PDF
                        </button>
                      )}
                    </div>

                    <button type="button" onClick={reset} className="w-full h-12 rounded-full border border-[var(--border)] bg-transparent text-[14px] font-semibold cursor-pointer hover:bg-[var(--surface-2)] transition-all">
                      New Analysis
                    </button>
                  </div>

                  {/* COLUMN 2: Tabs, Details, Verdicts & Findings (lg:col-span-5 or lg:col-span-8) */}
                  <div className={`space-y-6 transition-all duration-500 ${chatOpen ? 'lg:col-span-6' : 'lg:col-span-8'}`}>
                    {/* Segmented Controller */}
                    <div className="flex justify-center mb-6">
                      <div className="inline-flex p-1 rounded-full bg-[var(--surface-2)] border border-[var(--border)] backdrop-blur-md shadow-inner gap-1 relative">
                        <button
                          type="button"
                          onClick={() => setStoryTab('static')}
                          className={`relative px-5 py-2 rounded-full text-[13px] font-semibold tracking-tight transition-all duration-300 border-0 cursor-pointer z-10 ${
                            storyTab === 'static'
                              ? 'text-[var(--blue)] drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]'
                              : 'text-[var(--muted)] hover:text-[var(--text)]'
                          }`}
                        >
                          {storyTab === 'static' && (
                            <motion.div
                              layoutId="activeStoryTab"
                              className="absolute inset-0 bg-[var(--blue)]/10 border border-[var(--blue)]/30 rounded-full shadow-[0_0_15px_rgba(59,130,246,0.15)] -z-10"
                              transition={{ type: "spring", stiffness: 380, damping: 30 }}
                            />
                          )}
                          🔎 Static Audit
                        </button>
                        <button
                          type="button"
                          onClick={() => setStoryTab('dynamic')}
                          className={`relative px-5 py-2 rounded-full text-[13px] font-semibold tracking-tight transition-all duration-300 border-0 cursor-pointer flex items-center gap-1.5 z-10 ${
                            storyTab === 'dynamic'
                              ? 'text-[var(--blue)] drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]'
                              : 'text-[var(--muted)] hover:text-[var(--text)]'
                          }`}
                        >
                          {storyTab === 'dynamic' && (
                            <motion.div
                              layoutId="activeStoryTab"
                              className="absolute inset-0 bg-[var(--blue)]/10 border border-[var(--blue)]/30 rounded-full shadow-[0_0_15px_rgba(59,130,246,0.15)] -z-10"
                              transition={{ type: "spring", stiffness: 380, damping: 30 }}
                            />
                          )}
                          ⚡ Dynamic Audit
                          {current.progress?.dynamic_sandbox === "RUNNING" && (
                            <span className="w-1.5 h-1.5 rounded-full bg-[var(--blue)] animate-ping shrink-0" />
                          )}
                          {(!current.evidence?.dynamic_analysis || current.progress?.dynamic_sandbox === "SKIPPED") && (
                            <span className="text-[10px] opacity-60">🔒</span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            if (hasDynamic && current.progress?.dynamic_sandbox === 'COMPLETED') {
                              setStoryTab('final');
                            }
                          }}
                          disabled={!hasDynamic || current.progress?.dynamic_sandbox !== 'COMPLETED'}
                          className={`relative px-5 py-2 rounded-full text-[13px] font-semibold tracking-tight transition-all duration-300 border-0 cursor-pointer flex items-center gap-1.5 z-10 ${
                            storyTab === 'final'
                              ? 'text-[var(--blue)] drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]'
                              : 'text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50 disabled:cursor-not-allowed'
                          }`}
                        >
                          {storyTab === 'final' && (
                            <motion.div
                              layoutId="activeStoryTab"
                              className="absolute inset-0 bg-[var(--blue)]/10 border border-[var(--blue)]/30 rounded-full shadow-[0_0_15px_rgba(59,130,246,0.15)] -z-10"
                              transition={{ type: "spring", stiffness: 380, damping: 30 }}
                            />
                          )}
                          📊 Final Report
                          {(!hasDynamic || current.progress?.dynamic_sandbox !== 'COMPLETED') && (
                            <span className="text-[10px] opacity-60">🔒</span>
                          )}
                        </button>
                      </div>
                    </div>

                    {storyTab === 'static' ? (
                      <>
                        {/* STATIC AUDIT STORIES */}
                        {activeSummaryText && (
                          <div className="security-card p-6 space-y-3">
                            <div className="flex items-center gap-2 mb-1 border-b border-[var(--border)]/50 pb-2 text-[var(--blue)]">
                              <span className="text-[14px]">🔎</span>
                              <span className="text-[12px] uppercase tracking-wider font-bold">Static Audit</span>
                            </div>
                            <div className={summaryExpanded ? '' : 'line-clamp-[6] overflow-hidden'}>
                              <MarkdownBody text={activeSummaryText} />
                            </div>
                            <button
                              type="button"
                              onClick={() => setSummaryExpanded(e => !e)}
                              className="text-[13px] text-[var(--blue)] bg-transparent border-0 cursor-pointer p-0 hover:opacity-80 font-semibold"
                            >
                              {summaryExpanded ? 'Show less ↑' : 'Show more ↓'}
                            </button>
                          </div>
                        )}

                        {activeRiskDecomposition?.components && (
                          <div className="security-card p-6 space-y-4">
                            <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">Risk Breakdown</p>
                            <div className="space-y-3">
                              {Object.entries(activeRiskDecomposition.components).map(([key, val]) => (
                                <div key={key}>
                                  <div className="flex justify-between text-[13px] mb-1 capitalize">
                                    <span className="text-[var(--muted)]">{key.replace('_', ' ')}</span>
                                    <span className="tabular-nums font-semibold" style={{ color: accent }}>{String(val)}/100</span>
                                  </div>
                                  <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.min(100, Number(val) || 0)}%`, backgroundColor: accent }} />
                                  </div>
                                </div>
                              ))}
                            </div>
                            {activeRiskDecomposition.summary && (
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed pt-2 border-t border-[var(--border)]/30">{activeRiskDecomposition.summary}</p>
                            )}
                          </div>
                        )}

                        {/* Static Engines Telemetry */}
                        <div className="security-card p-6 space-y-4">
                          <div>
                            <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-1 font-semibold tracking-wider">Static Telemetry</p>
                            <p className="text-[13px] text-[var(--muted)]">Raw security engine findings across each decompiled layer.</p>
                          </div>

                          <div className="flex gap-1 overflow-x-auto pb-2 border-b border-[var(--border)] -mx-6 px-6 no-scrollbar">
                            {(['manifest', 'apkid', 'quark', 'androguard', 'secrets', 'network', 'compliance'] as const).map((tab) => (
                              <button
                                key={tab}
                                type="button"
                                onClick={() => setStaticTab(tab)}
                                className={`px-4 py-2 text-[13px] font-semibold whitespace-nowrap rounded-full cursor-pointer transition-all border-0 ${
                                  staticTab === tab
                                    ? 'bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/30'
                                    : 'bg-transparent text-[var(--muted)] hover:text-[var(--text)]'
                                }`}
                              >
                                {tab === 'manifest' && 'Manifest'}
                                {tab === 'apkid' && 'APKiD VM'}
                                {tab === 'quark' && 'Quark Behavioral'}
                                {tab === 'androguard' && 'Androguard DEX'}
                                {tab === 'secrets' && 'Deep Secrets'}
                                {tab === 'network' && 'Network Config'}
                                {tab === 'compliance' && 'Semgrep AST'}
                              </button>
                            ))}
                          </div>

                          <div className="pt-2">
                            {staticTab === 'manifest' && (
                              <div className="space-y-4 animate-fadeIn">
                                {current.evidence?.permissions && current.evidence.permissions.length > 0 ? (
                                  <div className="space-y-2">
                                    <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Permissions</p>
                                    {current.evidence.permissions.map((p, i) => (
                                      <div key={i} className="flex justify-between items-center py-2.5 px-3.5 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] transition-all duration-300 hover:border-[var(--border-hover)] hover:bg-[var(--surface-2)] hover:shadow-[0_0_12px_rgba(59,130,246,0.06)] group">
                                        <div>
                                          <p className="text-[13px] font-mono text-[var(--text)] break-all">{p.name}</p>
                                          {p.description && <p className="text-[12px] text-[var(--muted)] mt-0.5">{p.description}</p>}
                                        </div>
                                        <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-[var(--red)]/10 text-[var(--red)] border border-[var(--red)]/20 shrink-0 shadow-sm transition-all duration-300 group-hover:scale-105 tabular-nums">+{p.risk_score} pts</span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <p className="text-[13px] text-[var(--muted)]">No dangerous permissions requested.</p>
                                )}

                                {current.evidence?.exported_components && current.evidence.exported_components.length > 0 && (
                                  <div className="space-y-2 pt-2 border-t border-[var(--border)]">
                                    <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Exported Components</p>
                                    {current.evidence.exported_components.map((ec, i) => (
                                      <div key={i} className="py-3 px-3.5 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] transition-all duration-300 hover:border-[var(--border-hover)] hover:bg-[var(--surface-2)] hover:shadow-[0_0_12px_rgba(59,130,246,0.06)]">
                                        <div className="flex justify-between items-start gap-3">
                                          <p className="text-[13px] font-mono break-all font-semibold text-[var(--text)]">{ec.name}</p>
                                          <span className="text-[11.5px] uppercase px-2.5 py-0.5 rounded bg-[var(--surface)] text-[var(--muted)] border border-[var(--border)] shrink-0 font-semibold">{ec.type}</span>
                                        </div>
                                        <p className="text-[12px] text-[var(--muted)] mt-1">{ec.description}</p>
                                      </div>
                                    ))}
                                  </div>
                                )}

                                {current.evidence?.dangerous_manifest_flags && current.evidence.dangerous_manifest_flags.length > 0 && (
                                  <div className="space-y-2 pt-2 border-t border-[var(--border)]">
                                    <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Manifest Flags</p>
                                    {current.evidence.dangerous_manifest_flags.map((f, i) => (
                                      <div key={i} className="flex justify-between items-center py-2.5 px-3.5 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] transition-all duration-300 hover:border-[var(--border-hover)] hover:bg-[var(--surface-2)] hover:shadow-[0_0_12px_rgba(59,130,246,0.06)] group">
                                        <div>
                                          <p className="text-[13px] font-mono font-semibold text-[var(--text)]">{f.flag}</p>
                                          <p className="text-[12px] text-[var(--muted)] mt-0.5">{f.description}</p>
                                        </div>
                                        <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-[var(--red)]/10 text-[var(--red)] border border-[var(--red)]/20 shrink-0 shadow-sm transition-all duration-300 group-hover:scale-105 tabular-nums">+{f.risk_score} pts</span>
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}

                            {staticTab === 'apkid' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const avm = current.evidence?.malware_rule_hits?.filter(x => x.type === "Anti-VM Check") || [];
                                  const obf = current.evidence?.obfuscation_signals?.filter(x => x.type === "Obfuscator" || x.type === "Packer" || x.type === "Manipulator") || [];
                                  if (avm.length === 0 && obf.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No packer, compiler manipulation, or VM evasion signatures detected.</p>;
                                  }
                                  return (
                                    <div className="space-y-4">
                                      {avm.length > 0 && (
                                        <div className="space-y-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Evasion Checks</p>
                                          {avm.map((a, i) => (
                                            <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)]">
                                              <div>
                                                <p className="text-[14px] font-semibold">{a.match || "Anti-VM Indicator"}</p>
                                                <p className="text-[12px] text-[var(--muted)] mt-0.5">{a.description}</p>
                                              </div>
                                              <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)]">+{a.risk_score}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                      {obf.length > 0 && (
                                        <div className="space-y-2 border-t border-[var(--border)] pt-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Obfuscation</p>
                                          {obf.map((o, i) => (
                                            <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)]">
                                              <div>
                                                <p className="text-[14px] font-semibold">{o.match || "Obfuscated Target"}</p>
                                                <p className="text-[12px] text-[var(--muted)] mt-0.5">{o.description}</p>
                                              </div>
                                              <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)]">+{o.risk_score}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'quark' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const quarkHits = current.evidence?.malware_rule_hits?.filter(x => x.rule && !x.rule.includes("MobSF") && !x.rule.includes("semgrep")) || [];
                                  if (quarkHits.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No Quark behavioral rules triggered.</p>;
                                  }
                                  return (
                                    <div className="space-y-3">
                                      {quarkHits.map((q, i) => (
                                        <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/40 rounded-2xl border border-[var(--border)] space-y-1.5">
                                          <div className="flex justify-between items-start gap-3">
                                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20 font-semibold">{q.rule}</span>
                                            <div className="relative group/tooltip">
                                              <span className="text-[11px] px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--muted)] font-medium cursor-help hover:text-[var(--text)] transition-colors">
                                                Confidence: {q.confidence}
                                              </span>
                                              <div className="absolute right-0 bottom-full mb-2 w-64 p-2.5 bg-zinc-950 text-[11px] text-zinc-300 rounded-lg shadow-xl border border-zinc-800 hidden group-hover/tooltip:block z-50 leading-relaxed font-normal normal-case pointer-events-none">
                                                {q.confidence === '100%'
                                                  ? '100% Confidence: The exact bytecode call sequences, parameters, and instruction orders are fully matched and resolved statically.'
                                                  : `Confidence: ${q.confidence}. The static bytecode heuristic matched the API combination flow, but some optional classes/methods were unresolved.`
                                                }
                                              </div>
                                            </div>
                                          </div>
                                          <p className="text-[14px] font-semibold leading-snug">{q.description}</p>
                                          <div className="flex justify-between items-center text-[12px] text-[var(--muted)] pt-1 border-t border-[var(--border)]/30">
                                            <span>Severity: {q.severity}</span>
                                            <span className="text-[var(--red)] font-semibold">+{q.risk_score} pts</span>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'compliance' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const semgrepHits = current.evidence?.malware_rule_hits?.filter(x => x.rule?.includes("semgrep")) || [];
                                  const cryptoSemgrep = current.evidence?.crypto_issues?.filter(x => x.type === "semgrep") || [];
                                  const totalSemgrep = [...semgrepHits, ...cryptoSemgrep];
                                  
                                  if (totalSemgrep.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No Semgrep AST violations found.</p>;
                                  }
                                  return (
                                    <div className="space-y-4">
                                      <div className="space-y-2">
                                        <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Semgrep MASTG AST Violations</p>
                                        {totalSemgrep.map((s, i) => (
                                          <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/40 rounded-2xl border border-[var(--border)] space-y-1.5">
                                            <div className="flex justify-between items-start gap-3">
                                              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--red)]/15 text-[var(--red)] font-bold border border-[var(--red)]/20 shrink-0">{(s as any).severity || "HIGH"}</span>
                                              <span className="text-[12px] font-semibold text-[var(--red)]">+{s.risk_score || 10} pts</span>
                                            </div>
                                            <p className="text-[14px] font-semibold">{s.description || (s as any).rule}</p>
                                            {(s as any).file && <p className="text-[11px] font-mono text-[var(--muted)] break-all bg-[var(--surface)] py-1 px-2 rounded">{(s as any).file}</p>}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'androguard' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const chains = current.evidence?.reflection_dynamic_loading?.filter(x => x.type && x.description?.includes("API chain")) || [];
                                  const superclasses = current.evidence?.obfuscation_signals?.filter(x => x.class) || [];
                                  const strings = current.evidence?.suspicious_urls?.filter(x => x.type && !x.url) || [];
                                  if (chains.length === 0 && superclasses.length === 0 && strings.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No suspicious static bytecode call chains or extensions matched.</p>;
                                  }
                                  return (
                                    <div className="space-y-4">
                                      {chains.length > 0 && (
                                        <div className="space-y-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">API Call Chains</p>
                                          {chains.map((c, i) => (
                                            <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] flex justify-between items-center gap-3">
                                              <div>
                                                <p className="text-[14px] font-semibold">{c.type}</p>
                                                <p className="text-[12px] text-[var(--muted)] mt-0.5">{c.description}</p>
                                              </div>
                                              <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                      {superclasses.length > 0 && (
                                        <div className="space-y-2 border-t border-[var(--border)] pt-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Extended Classes</p>
                                          {superclasses.map((s, i) => (
                                            <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)]">
                                              <div className="flex justify-between items-start gap-3">
                                                <p className="text-[13px] font-mono break-all font-semibold">{s.class}</p>
                                                <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] shrink-0">+{s.risk_score}</span>
                                              </div>
                                              <p className="text-[12px] text-[var(--muted)] mt-1">{s.description}</p>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                      {strings.length > 0 && (
                                        <div className="space-y-2 border-t border-[var(--border)] pt-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Bytecode Patterns</p>
                                          {strings.map((str, i) => (
                                            <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] flex justify-between items-start gap-3">
                                              <div>
                                                <p className="text-[13px] font-semibold">{str.type}</p>
                                                <p className="text-[12px] font-mono text-[var(--muted)] break-all mt-0.5">{str.value}</p>
                                              </div>
                                              <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{str.risk_score}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'secrets' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const secrets = current.evidence?.hardcoded_secrets || [];
                                  if (secrets.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No credentials, keys, or hardcoded tokens leaked.</p>;
                                  }
                                  return (
                                    <div className="space-y-3">
                                      {secrets.map((s, i) => (
                                        <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/40 rounded-2xl border border-[var(--border)] space-y-1.5">
                                          <div className="flex justify-between items-start gap-3">
                                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--red)]/15 text-[var(--red)] font-bold border border-[var(--red)]/20">{s.severity}</span>
                                            <span className="text-[12px] font-semibold text-[var(--red)]">+{s.risk_score} pts</span>
                                          </div>
                                          <p className="text-[14px] font-semibold">{s.type}</p>
                                          {s.file && <p className="text-[11px] font-mono text-[var(--muted)] break-all bg-[var(--surface)] py-1 px-2 rounded">{s.file}</p>}
                                          <p className="text-[13px] text-[var(--muted)] pt-0.5 leading-relaxed">{s.description}</p>
                                        </div>
                                      ))}
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'network' && (
                              <div className="space-y-4 animate-fadeIn">
                                {(() => {
                                  const cleartextUrls = current.evidence?.suspicious_urls?.filter(x => x.url) || [];
                                  const configIssues = current.evidence?.network_indicators?.filter(x => x.source === "xml") || [];
                                  const codeHttpIssues = current.evidence?.network_indicators?.filter(x => x.source === "jadx") || [];
                                  if (cleartextUrls.length === 0 && configIssues.length === 0 && codeHttpIssues.length === 0) {
                                    return <p className="text-[13px] text-[var(--muted)]">No cleartext HTTP permissions or domain indicators reported.</p>;
                                  }
                                  return (
                                    <div className="space-y-4">
                                      {configIssues.length > 0 && (
                                        <div className="space-y-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Network Config</p>
                                          {configIssues.map((c, i) => (
                                            <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)] flex justify-between items-center gap-3">
                                              <div>
                                                <p className="text-[14px] font-semibold">{c.type}</p>
                                                <p className="text-[12px] text-[var(--muted)] mt-0.5">{c.description}</p>
                                              </div>
                                              <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                      {codeHttpIssues.length > 0 && (
                                        <div className="space-y-2 border-t border-[var(--border)] pt-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Cleartext Protocols</p>
                                          <div className="max-h-[250px] overflow-y-auto space-y-2 pr-1">
                                            {codeHttpIssues.map((c, i) => (
                                              <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)]">
                                                <div className="flex justify-between items-center gap-3">
                                                  <p className="text-[14px] font-semibold">{c.type}</p>
                                                  <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                                </div>
                                                {c.file && <p className="text-[11px] font-mono text-[var(--muted)] break-all mt-1 bg-[var(--surface)] py-0.5 px-1.5 rounded inline-block">{c.file}</p>}
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                      {cleartextUrls.length > 0 && (
                                        <div className="space-y-2 border-t border-[var(--border)] pt-2">
                                          <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Suspicious URLs</p>
                                          <div className="max-h-[300px] overflow-y-auto space-y-2 pr-1">
                                            {cleartextUrls.map((url, i) => (
                                              <div key={i} className="py-2 px-3 bg-[var(--surface-2)]/50 rounded-xl border border-[var(--border)]">
                                                <p className="text-[13px] font-mono break-all text-[var(--text)] font-semibold">{url.url}</p>
                                                {url.file && <p className="text-[11px] font-mono text-[var(--muted)] break-all mt-1 bg-[var(--surface)] py-0.5 px-1.5 rounded inline-block">{url.file}</p>}
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  );
                                })()}
                              </div>
                            )}
                          </div>
                        </div>

                        {activeAttackTechniques.length > 0 && (
                          <div className="space-y-3">
                            <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">MITRE ATT&CK Matrix</p>
                            <div className="space-y-2">
                              {(() => {
                                const items = activeAttackTechniques;
                                const showLimit = 6;
                                const hasMore = items.length > showLimit;
                                const visibleItems = (hasMore && !mitreExpanded) ? items.slice(0, showLimit) : items;
                                const remainingCount = items.length - showLimit;

                                return (
                                  <>
                                    {visibleItems.map((t) => {
                                      const isExpanded = !!expandedTechniques[t.id];
                                      return (
                                        <div
                                          key={t.id}
                                          onClick={() => setExpandedTechniques(prev => ({ ...prev, [t.id]: !prev[t.id] }))}
                                          className="rounded-2xl bg-[var(--surface)] border border-[var(--border)] p-4 space-y-1.5 hover:border-[var(--blue)]/40 hover:bg-[var(--surface-2)]/20 cursor-pointer select-none transition-all duration-300"
                                        >
                                          <div className="flex items-start justify-between gap-3">
                                            <div className="flex items-center gap-2 flex-wrap">
                                              <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20 font-semibold">{t.id}</span>
                                              <span className="text-[14px] font-semibold">{t.name}</span>
                                              {t.sources && t.sources.length > 0 && (
                                                <span className="text-[11.5px] text-[var(--muted)]">({t.sources.length} detection{t.sources.length > 1 ? 's' : ''})</span>
                                              )}
                                            </div>
                                            <div className="flex items-center gap-2 shrink-0">
                                              {t.tactic && (
                                                <span className="text-[11px] px-2 py-0.5 rounded-full bg-[var(--surface-2)] text-[var(--muted)] whitespace-nowrap border border-[var(--border)]">{t.tactic}</span>
                                              )}
                                              <span className={`text-[10px] text-[var(--muted)] transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>▼</span>
                                            </div>
                                          </div>
                                          {isExpanded && t.sources && t.sources.length > 0 && (
                                            <ul className="space-y-1.5 pt-2.5 border-t border-[var(--border)] mt-2">
                                              {t.sources.map((s, si) => (
                                                <li key={si} className="text-[13px] text-[var(--muted)] pl-3 border-l-2 border-[var(--blue)]/30">
                                                  <span className="text-[var(--text)] font-medium">{String(s.source || '')}</span>{s.detail ? ` — ${String(s.detail)}` : ''}
                                                </li>
                                              ))}
                                            </ul>
                                          )}
                                        </div>
                                      );
                                    })}
                                    {hasMore && (
                                      <button
                                        type="button"
                                        onClick={() => setMitreExpanded(!mitreExpanded)}
                                        className="w-full py-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)]/40 backdrop-blur-md text-[13px] text-[var(--blue)] font-semibold cursor-pointer hover:bg-[var(--blue)]/10 hover:border-[var(--blue)]/30 transition-all duration-200 flex items-center justify-center gap-2"
                                      >
                                        {mitreExpanded ? 'Show less ↑' : `Read (${remainingCount} more) ↓`}
                                      </button>
                                    )}
                                  </>
                                );
                              })()}
                            </div>
                          </div>
                        )}

                        {(!current.evidence?.dynamic_analysis || current.progress?.dynamic_sandbox === "SKIPPED") && (
                          <div className="security-card p-6 border border-[var(--border)] space-y-4">
                            <div className="flex items-center gap-2 text-[var(--blue)]">
                              <span className="text-[16px]">⚡</span>
                              <p className="text-[12px] uppercase tracking-widest font-semibold tracking-wider">Run Runtime Tracing</p>
                            </div>
                            <div className="space-y-2">
                              <p className="text-[15px] font-medium">Dynamic Sandbox</p>
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                                Analyze app behavior in a live sandbox. kavach runs the app on an Android device to capture dynamic network traffic, file activity, and API calls.
                              </p>
                            </div>
                            <button
                              type="button"
                              onClick={startDynamic}
                              disabled={busy}
                              className="w-full h-11 rounded-full bg-[var(--blue)] text-white text-[14px] font-semibold cursor-pointer hover:opacity-90 disabled:opacity-50 transition-opacity flex items-center justify-center gap-2"
                            >
                              ⚡ Run Dynamic Sandbox
                            </button>
                          </div>
                        )}
                      </>
                    ) : (
                      <>
                        {/* DYNAMIC EXECUTION STORIES */}
                        {current.progress?.dynamic_sandbox === "RUNNING" ? (
                          <div className="security-card p-6 border border-[var(--blue)]/30 space-y-4">
                            <div className="flex items-center justify-between">
                              <p className="text-[12px] uppercase tracking-widest text-[var(--blue)] font-bold animate-pulse">⚡ Sandbox Running</p>
                              <span className="text-[11px] font-mono text-[var(--muted)] animate-pulse">Tracing APIs live ...</span>
                            </div>
                            <div className="space-y-3">
                              <p className="text-[15px] font-semibold">Dynamic Instrumentation Tracing</p>
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                                Booting Android sandbox, preparing Frida hook packs, and initiating UI triggers. Telemetry signals are recorded in real-time.
                              </p>
                              <div className="relative h-2 w-full rounded-full bg-[var(--surface-2)] overflow-hidden border border-[var(--border)]">
                                <div className="h-full bg-[var(--blue)] animate-pulse rounded-full" style={{ width: '45%' }} />
                              </div>
                            </div>
                            
                            <div className="space-y-2 border-t border-[var(--border)] pt-4">
                              <p className="text-[11px] uppercase tracking-widest text-[var(--muted)] font-semibold">Sandbox Execution Logs</p>
                              <div className="max-h-40 overflow-y-auto font-mono text-[11px] text-[var(--blue)] space-y-1 pr-1 bg-[var(--surface-2)]/50 p-3 rounded-2xl border border-[var(--border)] scrollbar-thin select-none">
                                {(() => {
                                  const dynLogs = current.logs?.filter(x => x.includes("DYNAMIC") || x.includes("Frida") || x.includes("PLAYBOOK") || x.includes("download") || x.includes("sandbox")) || [];
                                  if (dynLogs.length === 0) {
                                    return <p className="text-[11px] text-[var(--muted)] animate-pulse">Booting QEMU device image...</p>;
                                  }
                                  return dynLogs.map((log, i) => (
                                    <p key={i} className="break-all">{log}</p>
                                  ));
                                })()}
                              </div>
                            </div>
                          </div>
                        ) : (!current.evidence?.dynamic_analysis || current.progress?.dynamic_sandbox === "SKIPPED") ? (
                          <div className="security-card p-6 border border-[var(--border)] space-y-6 text-center py-10">
                            <div className="w-16 h-16 rounded-full bg-zinc-900 border border-zinc-800 flex items-center justify-center mx-auto mb-4 text-[24px]">
                              🔒
                            </div>
                            <div className="space-y-2 max-w-md mx-auto">
                              <p className="text-[18px] font-bold text-zinc-100">Dynamic Sandbox is Locked</p>
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                                This app has only undergone static checks. Run dynamic sandbox analysis to observe runtime overlays, network C2 traffic, and live API hooks.
                              </p>
                            </div>
                            <button
                              type="button"
                              onClick={startDynamic}
                              disabled={busy}
                              className="h-11 px-8 rounded-full bg-[var(--blue)] text-white text-[14px] font-semibold cursor-pointer hover:opacity-90 disabled:opacity-50 transition-all flex items-center justify-center gap-2 mx-auto mt-4"
                            >
                              ⚡ Run Dynamic Sandbox
                            </button>
                          </div>
                        ) : storyTab === 'dynamic' ? (
                          <>
                            {activeSummaryText && (
                                  <div className="security-card p-6 space-y-3 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]">
                                    <div className="flex items-center gap-2 mb-1 border-b border-[var(--border)]/50 pb-2 text-indigo-400">
                                      <span className="text-[14px]">⚡</span>
                                      <span className="text-[12px] uppercase tracking-wider font-bold">Dynamic Audit</span>
                                    </div>
                                    <div className={summaryExpanded ? '' : 'line-clamp-[6] overflow-hidden'}>
                                      <MarkdownBody text={activeSummaryText} />
                                    </div>
                                    <button
                                      type="button"
                                      onClick={() => setSummaryExpanded(e => !e)}
                                      className="text-[13px] text-[var(--blue)] bg-transparent border-0 cursor-pointer p-0 hover:opacity-80 font-semibold"
                                    >
                                      {summaryExpanded ? 'Show less ↑' : 'Show more ↓'}
                                    </button>
                                  </div>
                                )}

                                {activeRiskDecomposition?.components && (
                                  <div className="security-card p-6 space-y-4">
                                    <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">Risk Breakdown</p>
                                <div className="space-y-3">
                                  {Object.entries(activeRiskDecomposition.components).map(([key, val]) => (
                                    <div key={key}>
                                      <div className="flex justify-between text-[13px] mb-1 capitalize">
                                        <span className="text-[var(--muted)]">{key.replace('_', ' ')}</span>
                                        <span className="tabular-nums font-semibold" style={{ color: accent }}>{String(val)}/100</span>
                                      </div>
                                      <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.min(100, Number(val) || 0)}%`, backgroundColor: accent }} />
                                      </div>
                                    </div>
                                  ))}
                                </div>
                                {activeRiskDecomposition.summary && (
                                  <p className="text-[13px] text-[var(--muted)] leading-relaxed pt-2 border-t border-[var(--border)]/30">{activeRiskDecomposition.summary}</p>
                                )}
                              </div>
                            )}

                            <div className="security-card p-6 border border-[var(--border)]">
                              <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-4 font-semibold tracking-wider">Sandbox Telemetry</p>
                              <DynamicAnalysisOperatorSmokeView activeResult={toDynamicUi(current)} />
                            </div>

                            {activeAttackTechniques.length > 0 && (
                              <div className="space-y-3">
                                <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">MITRE ATT&CK Matrix</p>
                                <div className="space-y-2">
                                  {(() => {
                                    const items = activeAttackTechniques;
                                    const showLimit = 6;
                                    const hasMore = items.length > showLimit;
                                    const visibleItems = (hasMore && !mitreExpanded) ? items.slice(0, showLimit) : items;
                                    const remainingCount = items.length - showLimit;

                                    return (
                                      <>
                                        {visibleItems.map((t) => {
                                          const isExpanded = !!expandedTechniques[t.id];
                                          return (
                                            <div
                                              key={t.id}
                                              onClick={() => setExpandedTechniques(prev => ({ ...prev, [t.id]: !prev[t.id] }))}
                                              className="rounded-2xl bg-[var(--surface)] border border-[var(--border)] p-4 space-y-1.5 hover:border-[var(--blue)]/40 hover:bg-[var(--surface-2)]/20 cursor-pointer select-none transition-all duration-300"
                                            >
                                              <div className="flex items-start justify-between gap-3">
                                                <div className="flex items-center gap-2 flex-wrap">
                                                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20 font-semibold">{t.id}</span>
                                                  <span className="text-[14px] font-semibold">{t.name}</span>
                                                  {t.sources && t.sources.length > 0 && (
                                                    <span className="text-[11.5px] text-[var(--muted)]">({t.sources.length} detection{t.sources.length > 1 ? 's' : ''})</span>
                                                  )}
                                                </div>
                                                <div className="flex items-center gap-2 shrink-0">
                                                  {t.tactic && (
                                                    <span className="text-[11px] px-2 py-0.5 rounded-full bg-[var(--surface-2)] text-[var(--muted)] whitespace-nowrap border border-[var(--border)]">{t.tactic}</span>
                                                  )}
                                                  <span className={`text-[10px] text-[var(--muted)] transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>▼</span>
                                                </div>
                                              </div>
                                              {isExpanded && t.sources && t.sources.length > 0 && (
                                                <ul className="space-y-1.5 pt-2.5 border-t border-[var(--border)] mt-2">
                                                  {t.sources.map((s, si) => (
                                                    <li key={si} className="text-[13px] text-[var(--muted)] pl-3 border-l-2 border-[var(--blue)]/30">
                                                      <span className="text-[var(--text)] font-medium">{String(s.source || '')}</span>{s.detail ? ` — ${String(s.detail)}` : ''}
                                                    </li>
                                                  ))}
                                                </ul>
                                              )}
                                            </div>
                                          );
                                        })}
                                        {hasMore && (
                                          <button
                                            type="button"
                                            onClick={() => setMitreExpanded(!mitreExpanded)}
                                            className="w-full py-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)]/40 backdrop-blur-md text-[13px] text-[var(--blue)] font-semibold cursor-pointer hover:bg-[var(--blue)]/10 hover:border-[var(--blue)]/30 transition-all duration-200 flex items-center justify-center gap-2"
                                          >
                                            {mitreExpanded ? 'Show less ↑' : `Read (${remainingCount} more) ↓`}
                                          </button>
                                        )}
                                      </>
                                    );
                                  })()}
                                </div>
                              </div>
                            )}
                          </>
                        ) : (
                          <>
                            {/* FINAL COMBINED REPORT STORY */}
                            {activeSummaryText && (
                              <div className="security-card p-6 space-y-3 border border-amber-500/20 shadow-[0_0_15px_rgba(245,158,11,0.05)]">
                                <div className="flex items-center gap-2 mb-1 border-b border-[var(--border)]/50 pb-2 text-amber-400">
                                  <span className="text-[14px]">📊</span>
                                  <span className="text-[12px] uppercase tracking-wider font-bold">Final Advisory Report</span>
                                </div>
                                <div className={summaryExpanded ? '' : 'line-clamp-[10] overflow-hidden'}>
                                  <MarkdownBody text={activeSummaryText} />
                                </div>
                                <button
                                  type="button"
                                  onClick={() => setSummaryExpanded(e => !e)}
                                  className="text-[13px] text-[var(--blue)] bg-transparent border-0 cursor-pointer p-0 hover:opacity-80 font-semibold"
                                >
                                  {summaryExpanded ? 'Show less ↑' : 'Show more ↓'}
                                </button>
                              </div>
                            )}

                            {activeRiskDecomposition?.components && (
                              <div className="security-card p-6 space-y-4">
                                <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">Overall Risk Breakdown</p>
                                <div className="space-y-3">
                                  {Object.entries(activeRiskDecomposition.components).map(([key, val]) => (
                                    <div key={key}>
                                      <div className="flex justify-between text-[13px] mb-1 capitalize">
                                        <span className="text-[var(--muted)]">{key.replace('_', ' ')}</span>
                                        <span className="tabular-nums font-semibold" style={{ color: accent }}>{String(val)}/100</span>
                                      </div>
                                      <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.min(100, Number(val) || 0)}%`, backgroundColor: accent }} />
                                      </div>
                                    </div>
                                  ))}
                                </div>
                                {activeRiskDecomposition.summary && (
                                  <p className="text-[13px] text-[var(--muted)] leading-relaxed pt-2 border-t border-[var(--border)]/30">{activeRiskDecomposition.summary}</p>
                                )}
                              </div>
                            )}

                            <div className="security-card p-6 border border-[var(--border)]">
                              <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-4 font-semibold tracking-wider">Combined Risk Telemetry Matrix</p>
                              <DynamicAnalysisOperatorSmokeView activeResult={toDynamicUi(current)} />
                            </div>
                          </>
                        )}
                      </>
                    )}

                    <FindingsBlock title="Threats" items={activeThreats} />
                    <FindingsBlock title="Vulnerabilities" items={activeVulnerabilities} />

                    {activeRemediation.length > 0 && (
                      <div className="security-card p-6 space-y-3">
                        <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Remediation</p>
                        <ul className="space-y-2">
                          {activeRemediation.map((r, i) => {
                            const displayValue = typeof r === 'string'
                              ? r
                              : (r && typeof r === 'object'
                                  ? ((r as any).recommendation || (r as any).action || (r as any).description || (r as any).title || JSON.stringify(r))
                                  : String(r));
                            return (
                              <li key={i} className="text-[15px] pl-3 border-l-2 border-[var(--green)]">
                                {displayValue}
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* COLUMN 3: Sticky AI Analyst Sidebar (lg:col-span-3) */}
                  {chatOpen && (
                    <div className="lg:col-span-3 lg:sticky lg:top-6 h-[calc(100vh-140px)] max-h-[680px] flex flex-col security-card p-4 space-y-4 animate-fadeIn">
                      <div className="flex items-center justify-between border-b border-[var(--border)] pb-2 shrink-0">
                        <span className="text-[12px] uppercase tracking-wider font-bold text-[var(--blue)]">AI security analyst</span>
                        <button 
                          type="button" 
                          onClick={() => setChatOpen(false)} 
                          className="text-[11px] text-[var(--muted)] hover:text-[var(--text)] bg-transparent border-0 cursor-pointer"
                        >
                          Close
                        </button>
                      </div>
                      
                      <div className="flex-1 overflow-y-auto space-y-4 pr-1 scrollbar-thin min-h-0 no-scrollbar">
                        {chatLog.length === 0 && (
                          <div className="space-y-4 py-8 flex flex-col items-center">
                            <p className="text-[13px] text-[var(--muted)] text-center leading-relaxed">
                              Ask about fraud risk, remediation, or evidence — powered by Gemini.
                            </p>
                            <div className="w-full space-y-2 px-2 pt-4">
                              <p className="text-[11px] uppercase tracking-widest text-[var(--muted)] font-semibold mb-1">Suggested Prompts</p>
                              {[
                                "Is this APK safe to install?",
                                "Explain the dynamic C2 network traces",
                                "Show all high risk banking fraud signals"
                              ].map((phrase, idx) => (
                                <button
                                  key={idx}
                                  type="button"
                                  onClick={() => askChat(phrase)}
                                  className="w-full text-left py-2.5 px-3 bg-[var(--surface-2)]/50 border border-[var(--border)] rounded-xl text-[12.5px] text-zinc-300 hover:text-[var(--blue)] hover:border-[var(--blue)]/40 hover:bg-[var(--surface-2)] transition-all duration-300 cursor-pointer block font-medium"
                                >
                                  ✦ {phrase}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                        {chatLog.map((m, i) => (
                          <ChatBubble key={i} role={m.role} text={m.text} />
                        ))}
                        {chatBusy && (
                          <div className="flex gap-2 items-center text-[12px] text-[var(--muted)]">
                            <span className="w-6 h-6 rounded-full bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center animate-pulse">✦</span>
                            Gemini is thinking…
                          </div>
                        )}
                      </div>
                      
                      <div className="space-y-2 shrink-0 pt-2 border-t border-[var(--border)]">
                        <div className="flex gap-1.5">
                          <input
                            value={chatInput}
                            onChange={(e) => setChatInput(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && askChat()}
                            placeholder="Ask a question..."
                            className="flex-1 h-10 px-3.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] text-[13px] text-[var(--text)] outline-none focus:border-[var(--blue)]/50 focus:shadow-[0_0_10px_rgba(59,130,246,0.15)] transition-all duration-300"
                          />
                          <button 
                            type="button" 
                            onClick={() => askChat()} 
                            disabled={chatBusy} 
                            className="h-10 px-4 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[13px] font-bold border-0 cursor-pointer disabled:opacity-50 hover:opacity-90 active:scale-95 transition-all duration-200"
                          >
                            Send
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="py-5 text-center text-[11px] text-[var(--muted)]">IIT Hyderabad × Bank of India · APK deleted after analysis</footer>
    </div>
  );
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-[#f43f5e]/10', text: 'text-[#f43f5e]', border: 'border-l-[#f43f5e]' },
  HIGH:     { bg: 'bg-[#f43f5e]/10', text: 'text-[#f43f5e]', border: 'border-l-[#f43f5e]' },
  MEDIUM:   { bg: 'bg-[#f97316]/10', text: 'text-[#f97316]', border: 'border-l-[#f97316]' },
  LOW:      { bg: 'bg-[#10b981]/10', text: 'text-[#10b981]', border: 'border-l-[#10b981]' },
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
