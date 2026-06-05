'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch, fetchSandboxHealth, downloadReport, sendChat, triggerDynamicAnalysis, uploadApkDirect, fetchHistory, printExecutiveReport } from '../lib/api';
import { DEMO_ANALYSIS } from '../lib/demo';
import type { AnalysisDoc, ThreatLevel, VirusTotalSummary } from '../lib/types';
import { livelyScanHeadline, runningStepKeys } from '../lib/scan-messages';
import { MarkdownBody } from '../lib/chat-ui';

// Import modular components
import CanvasRain from '../components/CanvasRain';
import TerminalLogs from '../components/TerminalLogs';
import { ScoreCard } from '../components/ScoreCard';
import { AttackMapping } from '../components/AttackMapping';
import { ChatSidebar } from '../components/ChatSidebar';
import { TelemetryStream } from '../components/TelemetryStream';

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#10b981',
  LOW: '#10b981',
  MEDIUM: '#f97316',
  HIGH: '#f43f5e',
  CRITICAL: '#f43f5e',
};

export default function Home() {
  const [history, setHistory] = useState<AnalysisDoc[]>([]);
  const [dragActive, setDragActive] = useState(false);
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
  const [staticTab, setStaticTab] = useState<'manifest' | 'apkid' | 'quark' | 'androguard' | 'secrets' | 'network' | 'compliance' | 'virustotal'>('manifest');
  const [storyTab, setStoryTab] = useState<'static' | 'dynamic' | 'final'>('static');
  const [reportTier, setReportTier] = useState<'soc' | 'bank_agent' | 'ciso'>('soc');
  const [estSecondsRemaining, setEstSecondsRemaining] = useState(30);

  const loadHistory = useCallback(async () => {
    try {
      const hist = await fetchHistory();
      setHistory(hist);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchSandboxHealth().then((h) => setSandboxOk(h.sandbox_status === 'READY'));
    loadHistory();
  }, [loadHistory]);

  // Poll backend for live analysis status (replaces Firestore real-time listener)
  // Adaptive polling: only polls while backend processing is active.
  useEffect(() => {
    if (isDemo || !activeId) return;

    const isRunning = !active || 
                      active.status === 'PROCESSING' || 
                      active.progress?.dynamic_sandbox === 'RUNNING' || 
                      active.progress?.dynamic_sandbox === 'WAITING' ||
                      active.progress?.finalize === 'RUNNING' ||
                      active.progress?.finalize === 'WAITING';

    if (!isRunning) {
      return;
    }

    let cancelled = false;
    const poll = async () => {
      try {
        const res = await apiFetch(`/api/analysis/${activeId}`);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) {
            const nextActive = { id: activeId, ...data } as AnalysisDoc;
            setActive(nextActive);
            if (nextActive.evidence?.dynamic_analysis?.status === 'COMPLETED') {
              setStoryTab('final');
            }
            if (nextActive.status === 'COMPLETED' || nextActive.status === 'FAILED') {
              loadHistory();
            }
          }
        }
      } catch { /* ignore */ }
    };
    poll();
    const interval = setInterval(poll, 3000); // 3s optimized polling
    return () => { cancelled = true; clearInterval(interval); };
  }, [activeId, isDemo, active?.status, active?.progress?.dynamic_sandbox, active?.progress?.finalize]);



  const analyze = async () => {
    if (!file || busy) return;
    setError(null);
    setBusy(true);
    setUploading(true);
    setUploadPct(0);
    setActiveId(null);
    setIsDemo(false);
    setSummaryExpanded(false);
    setMitreExpanded(false);
    setStoryTab('static');

    const initialSeconds = Math.min(75, Math.max(25, Math.round(file.size / (1024 * 1024) * 0.6) + 20));
    setEstSecondsRemaining(initialSeconds);

    try {
      const data = await uploadApkDirect(file, null, 'anonymous', setUploadPct);
      setUploading(false);
      setActiveId(data.id);
      setFile(null);
      loadHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
      setUploading(false);
      setUploadPct(0);
    }
  };

  const startDynamic = async () => {
    if (!current || busy) return;
    setError(null);
    setBusy(true);
    try {
      await triggerDynamicAnalysis(current.id, 'anonymous');
      // Explicitly update local state to trigger polling restart
      setActive(prev => prev ? {
        ...prev,
        status: 'PROCESSING',
        progress: {
          ...prev.progress,
          dynamic_sandbox: 'RUNNING'
        }
      } : null);
      setActiveId(current.id);
      setSummaryExpanded(false);
      setMitreExpanded(false);
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
    setSummaryExpanded(false);
    setMitreExpanded(false);
    setStoryTab('final');
  }, []);

  const reset = () => {
    setActiveId(null);
    setActive(null);
    setIsDemo(false);
    setFile(null);
    setChatLog([]);
    setChatOpen(false);
    setSummaryExpanded(false);
    setMitreExpanded(false);
    setStoryTab('static');
    loadHistory();
  };

  const current = isDemo ? active : activeId ? active : null;
  const displayHistory = history;

  const view = useMemo(() => {
    if (current?.status === 'PROCESSING') {
      if (current?.progress?.dynamic_sandbox === 'RUNNING') {
        return 'result';
      }
      return 'scan';
    }
    if (busy || uploading) return 'scan';
    if (current?.status === 'COMPLETED' || current?.status === 'FAILED') return 'result';
    return 'home';
  }, [current, busy, uploading]);

  const scanHeadline = livelyScanHeadline(current?.progress, current?.logs, scanTick);
  const parallelSteps = runningStepKeys(current?.progress);

  const progressPercent = (() => {
    if (uploading) {
      return Math.min(15, Math.round(uploadPct * 0.15));
    }
    if (!current?.progress) return 15;
    
    const stepKeys = ['download', 'apktool', 'jadx', 'apkid', 'quark', 'net_sec', 'androguard', 'secrets', 'semgrep', 'trufflehog', 'gemini', 'finalize'];
    const completedCount = stepKeys.filter(k => current.progress?.[k] === 'COMPLETED').length;
    
    const staticPercent = 15 + Math.round((completedCount / stepKeys.length) * 80);
    return Math.min(95, staticPercent);
  })();

  const baseEstimate = (() => {
    if (uploading) {
      return Math.round((100 - uploadPct) * 0.15) + 20;
    }
    if (!current?.progress) return 20;

    const progress = current.progress;

    // Check if pipeline is finalized
    if (progress.finalize === 'COMPLETED') return 0;

    const serialPre = 2; // download
    const parallelPhase1 = 18; // apktool, jadx, apkid, quark, androguard (dominated by jadx)
    const parallelPhase2 = 8; // net_sec, secrets, trufflehog, semgrep (dominated by semgrep/trufflehog)

    let est = 0;

    // Download step
    if (progress.download !== 'COMPLETED') {
      est += serialPre;
    }

    // Parallel Phase 1 (apktool, jadx, apkid, quark, androguard)
    const p1Steps = ['apktool', 'jadx', 'apkid', 'quark', 'androguard'];
    const p1Done = p1Steps.every(k => progress[k] === 'COMPLETED');
    if (!p1Done) {
      if (progress.download !== 'COMPLETED') {
        est += parallelPhase1;
      } else {
        let maxRemaining = 0;
        if (progress.jadx !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 18);
        if (progress.apktool !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 4);
        if (progress.quark !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 5);
        if (progress.apkid !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 3);
        if (progress.androguard !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 3);
        est += maxRemaining;
      }
    }

    // Parallel Phase 2 (net_sec, secrets, trufflehog, semgrep)
    const p2Steps = ['net_sec', 'secrets', 'trufflehog', 'semgrep'];
    const p2Done = p2Steps.every(k => progress[k] === 'COMPLETED');
    if (!p2Done) {
      if (!p1Done) {
        est += parallelPhase2;
      } else {
        let maxRemaining = 0;
        if (progress.semgrep !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 8);
        if (progress.trufflehog !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 6);
        if (progress.secrets !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 6);
        if (progress.net_sec !== 'COMPLETED') maxRemaining = Math.max(maxRemaining, 2);
        est += maxRemaining;
      }
    }

    // Gemini Synthesis & Finalize
    if (progress.gemini !== 'COMPLETED') {
      est += 8;
    }
    if (progress.finalize !== 'COMPLETED') {
      est += 2;
    }

    return Math.max(2, est);
  })();

  const displayedSecondsRemaining = estSecondsRemaining;

  // Reset estSecondsRemaining to 120 when dynamic sandbox starts running
  useEffect(() => {
    if (current?.progress?.dynamic_sandbox === 'RUNNING') {
      setEstSecondsRemaining(120);
    }
  }, [current?.progress?.dynamic_sandbox]);

  useEffect(() => {
    if (view === 'scan') {
      setEstSecondsRemaining((prev) => {
        // Enforce monotonically decreasing remaining time for static scans to prevent jumping back up.
        // We only adjust downwards when baseEstimate is lower than current prev, or if it is at the initial value (30).
        if (prev === 30 || baseEstimate < prev) {
          return baseEstimate;
        }
        return prev;
      });
    }
  }, [baseEstimate, view]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const f = e.dataTransfer.files[0];
      if (f.name.endsWith('.apk')) {
        setFile(f);
        setError(null);
      } else {
        setError('APK files only.');
      }
    }
  };

  useEffect(() => {
    const isStaticRunning = view === 'scan';
    const isDynamicRunning = current?.status === 'PROCESSING' && current?.progress?.dynamic_sandbox === 'RUNNING';

    if (!isStaticRunning && !isDynamicRunning) return;

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
  }, [view, current?.status, current?.progress?.dynamic_sandbox]);

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
    const ir = storyTab === 'static'
      ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report))
      : current?.investigation_report;

    if (reportTier === 'bank_agent') {
      return ir?.bank_agent_alert ?? 'No bank agent alert available.';
    }
    if (reportTier === 'ciso') {
      return ir?.ciso_brief ?? 'No CISO executive brief available.';
    }

    if (storyTab === 'static') {
      return current?.static_analysis?.investigation_report?.summary ?? (hasDynamic ? '' : current?.investigation_report?.summary ?? current?.investigation_report?.executive_verdict) ?? '';
    }
    if (storyTab === 'dynamic') {
      return current?.investigation_report?.dynamic_summary ?? current?.investigation_report?.summary ?? '';
    }
    return current?.investigation_report?.final_report ?? current?.investigation_report?.summary ?? '';
  }, [storyTab, reportTier, current, hasDynamic]);

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
    } catch (err: any) {
      const errMsg = err?.message || 'Could not reach analyst. Try again.';
      setChatLog((l) => [...l, { role: 'ai', text: errMsg }]);
    } finally {
      setChatBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden bg-[#030306]">
      {/* Dynamic Background Hacker Matrix Rain */}
      <CanvasRain />

      <header className={`flex items-center justify-between px-6 py-5 mx-auto w-full transition-all duration-500 z-10 ${view === 'result' ? 'max-w-[98%] px-8' : 'max-w-3xl'}`}>
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
        </div>
      </header>

      <main className={`flex-1 flex flex-col items-center px-6 pb-16 mx-auto w-full transition-all duration-500 z-10 ${view === 'result' ? 'max-w-[98%] px-8' : 'max-w-3xl'}`}>
        <AnimatePresence mode="wait">


          {view === 'home' && (
            <motion.div key="home" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full space-y-8 py-4">
              <div className="text-center space-y-2">
                <h1 className="text-[36px] font-bold tracking-tight bg-gradient-to-r from-zinc-100 to-zinc-400 bg-clip-text text-transparent">Analyze target APK</h1>
                <p className="text-[15px] text-[var(--muted)]">Initiate sandbox, manifest, and deep static auditing.</p>
              </div>

              <div 
                className="w-full relative"
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
              >
                <label className="block cursor-pointer group">
                  <input type="file" accept=".apk" className="sr-only" onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f?.name.endsWith('.apk')) { setFile(f); setError(null); }
                    else setError('APK files only.');
                  }} />
                  
                  {!file ? (
                    <div className={`rounded-3xl border border-dashed px-8 py-16 text-center transition-all duration-300 flex flex-col items-center justify-center space-y-5 relative overflow-hidden ${dragActive ? 'border-[var(--blue)] bg-zinc-900/40 shadow-[0_0_25px_rgba(77,144,254,0.15)] scale-[1.02]' : 'border-[var(--border)] bg-zinc-950/20 group-hover:border-[var(--blue-glow)] hover:bg-zinc-950/30'}`}>
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
              </div>

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

              {/* Progress Bar & Time Estimate */}
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
                    Est. time remaining: <strong className="text-[var(--blue)]">{displayedSecondsRemaining}s</strong>
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

              {/* Live Progress Terminal Logs stream during decompilation analysis */}
              <TerminalLogs logs={current?.logs || []} />

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
                  {/* COLUMN 1: Threat Score Gauge & Metadata (lg:col-span-4 or 3) */}
                  <ScoreCard
                    score={score}
                    level={level}
                    accent={accent}
                    absoluteScore={absoluteScore}
                    fraudScore={fraudScore}
                    filename={current.filename || 'Unknown'}
                    activeBadges={activeBadges}
                    logs={current.logs || []}
                    chatOpen={chatOpen}
                    setChatOpen={setChatOpen}
                    downloadReport={() => printExecutiveReport(current)}
                    isDemo={isDemo}
                    reset={reset}
                  />

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
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2 border-b border-[var(--border)]/50 pb-2">
                              <div className="flex items-center gap-2 text-[var(--blue)]">
                                <span className="text-[14px]">🔎</span>
                                <span className="text-[12px] uppercase tracking-wider font-bold">Static Audit</span>
                              </div>
                              <div className="flex bg-[var(--surface-2)]/80 p-0.5 rounded-lg border border-[var(--border)]/30 w-fit gap-1">
                                <button
                                  type="button"
                                  onClick={() => setReportTier('soc')}
                                  className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                    reportTier === 'soc'
                                      ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                      : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                  }`}
                                >
                                  🔧 SOC
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setReportTier('bank_agent')}
                                  className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                    reportTier === 'bank_agent'
                                      ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                      : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                  }`}
                                >
                                  🏦 Alert
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setReportTier('ciso')}
                                  className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                    reportTier === 'ciso'
                                      ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                      : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                  }`}
                                >
                                  📋 CISO
                                </button>
                              </div>
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
                              {Object.entries(activeRiskDecomposition.components)
                                .filter(([key]) => key !== "dynamic")
                                .map(([key, val]) => (
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
                            {(['manifest', 'apkid', 'quark', 'androguard', 'secrets', 'network', 'compliance', 'virustotal'] as const).map((tab) => (
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
                                {tab === 'virustotal' && '🛡 VirusTotal'}
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
                                              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--red)]/15 text-[var(--red)] font-bold border border-[var(--red)]/20 shrink-0">{s.severity || "HIGH"}</span>
                                              <span className="text-[12px] font-semibold text-[var(--red)]">+{s.risk_score || 10} pts</span>
                                            </div>
                                            <p className="text-[14px] font-semibold">{s.description || s.rule}</p>
                                            {s.file && <p className="text-[11px] font-mono text-[var(--muted)] break-all bg-[var(--surface)] py-1 px-2 rounded">{s.file}</p>}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  );
                                })()}
                              </div>
                            )}

                            {staticTab === 'virustotal' && (() => {
                              const vt = current.evidence?.virustotal as VirusTotalSummary | undefined;
                              const malicious = vt?.malicious || 0;
                              const undetected = vt?.undetected || 0;
                              const total = vt?.total || 0;
                              const permalink = vt?.permalink || '#';
                              return (
                                <div className="space-y-4 animate-fadeIn">
                                  {!vt || vt.status === 'skipped' ? (
                                    <p className="text-[13px] text-[var(--muted)]">VirusTotal integration requires a <code className="bg-[var(--surface)] px-1 rounded">VIRUSTOTAL_API_KEY</code> env variable. Set it in your backend <code>.env</code> file.</p>
                                  ) : vt.status === 'not_found' ? (
                                    <div className="py-4 px-5 bg-[var(--surface-2)]/40 rounded-2xl border border-[var(--border)] space-y-1">
                                      <p className="text-[14px] font-semibold text-[var(--muted)]">File not previously indexed</p>
                                      <p className="text-[13px] text-[var(--muted)]">This APK has not been scanned by VirusTotal before. It may be a novel or private sample.</p>
                                    </div>
                                  ) : vt.status === 'rate_limited' ? (
                                    <p className="text-[13px] text-[var(--red)]">VirusTotal free tier rate limit hit (4 req/min). Try again shortly.</p>
                                  ) : vt.status === 'success' ? (
                                    <div className="space-y-4">
                                      <div className="grid grid-cols-3 gap-3">
                                        <div className={`py-4 px-5 rounded-2xl border text-center space-y-1 ${ malicious > 0 ? 'bg-[var(--red)]/10 border-[var(--red)]/30' : 'bg-[var(--green)]/10 border-[var(--green)]/30'}`}>
                                          <p className={`text-[32px] font-bold tabular-nums ${ malicious > 0 ? 'text-[var(--red)]' : 'text-[var(--green)]'}`}>{malicious}</p>
                                          <p className="text-[12px] text-[var(--muted)] uppercase tracking-widest">Malicious</p>
                                        </div>
                                        <div className="py-4 px-5 rounded-2xl border border-[var(--border)] bg-[var(--surface-2)]/40 text-center space-y-1">
                                          <p className="text-[32px] font-bold tabular-nums text-[var(--muted)]">{undetected}</p>
                                          <p className="text-[12px] text-[var(--muted)] uppercase tracking-widest">Undetected</p>
                                        </div>
                                        <div className="py-4 px-5 rounded-2xl border border-[var(--border)] bg-[var(--surface-2)]/40 text-center space-y-1">
                                          <p className="text-[32px] font-bold tabular-nums">{total}</p>
                                          <p className="text-[12px] text-[var(--muted)] uppercase tracking-widest">Engines</p>
                                        </div>
                                      </div>
                                      {malicious > 0 && (
                                        <div className="py-2 px-4 rounded-xl bg-[var(--red)]/10 border border-[var(--red)]/20">
                                          <p className="text-[13px] font-semibold text-[var(--red)]">⚠ {malicious} of {total} antivirus engines flagged this file as malicious.</p>
                                        </div>
                                      )}
                                      <a href={permalink} target="_blank" rel="noopener noreferrer"
                                        className="flex items-center gap-2 text-[13px] text-[var(--blue)] hover:underline">
                                        View full VirusTotal report →
                                      </a>
                                    </div>
                                  ) : (
                                    <p className="text-[13px] text-[var(--muted)]">VT scan status: {vt?.status || 'unknown'}. {vt?.reason || ''}</p>
                                  )}
                                </div>
                              );
                            })()}

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

                        <AttackMapping
                          activeAttackTechniques={activeAttackTechniques}
                          expandedTechniques={expandedTechniques}
                          setExpandedTechniques={setExpandedTechniques}
                          mitreExpanded={mitreExpanded}
                          setMitreExpanded={setMitreExpanded}
                        />

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
                              <span className="text-[11px] font-mono text-[var(--muted)] animate-pulse">Est. remaining: {estSecondsRemaining}s</span>
                            </div>
                            <div className="space-y-3">
                              <p className="text-[15px] font-semibold">Dynamic Instrumentation Tracing</p>
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                                Booting Android sandbox, preparing Frida hook packs, and initiating UI triggers. Telemetry signals are recorded in real-time.
                              </p>
                              <div className="relative h-2 w-full rounded-full bg-[var(--surface-2)] overflow-hidden border border-[var(--border)]">
                                <div className="h-full bg-[var(--blue)] animate-pulse rounded-full transition-all duration-1000 ease-linear" style={{ width: `${Math.round(((120 - estSecondsRemaining) / 120) * 100)}%` }} />
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
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2 border-b border-[var(--border)]/50 pb-2">
                                  <div className="flex items-center gap-2 text-indigo-400">
                                    <span className="text-[14px]">⚡</span>
                                    <span className="text-[12px] uppercase tracking-wider font-bold">Dynamic Audit</span>
                                  </div>
                                  <div className="flex bg-[var(--surface-2)]/80 p-0.5 rounded-lg border border-[var(--border)]/30 w-fit gap-1">
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('soc')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'soc'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      🔧 SOC
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('bank_agent')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'bank_agent'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      🏦 Alert
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('ciso')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'ciso'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      📋 CISO
                                    </button>
                                  </div>
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
                                  {Object.entries(activeRiskDecomposition.components)
                                    .filter(([key]) => key !== "static")
                                    .map(([key, val]) => (
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

                            <TelemetryStream title="Sandbox Telemetry" current={current} />

                            <AttackMapping
                              activeAttackTechniques={activeAttackTechniques}
                              expandedTechniques={expandedTechniques}
                              setExpandedTechniques={setExpandedTechniques}
                              mitreExpanded={mitreExpanded}
                              setMitreExpanded={setMitreExpanded}
                            />
                          </>
                        ) : (
                          <>
                            {/* FINAL COMBINED REPORT STORY */}
                            {activeSummaryText && (
                              <div className="security-card p-6 space-y-3 border border-amber-500/20 shadow-[0_0_15px_rgba(245,158,11,0.05)]">
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2 border-b border-[var(--border)]/50 pb-2">
                                  <div className="flex items-center gap-2 text-amber-400">
                                    <span className="text-[14px]">📊</span>
                                    <span className="text-[12px] uppercase tracking-wider font-bold">Final Advisory Report</span>
                                  </div>
                                  <div className="flex bg-[var(--surface-2)]/80 p-0.5 rounded-lg border border-[var(--border)]/30 w-fit gap-1">
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('soc')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'soc'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      🔧 SOC
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('bank_agent')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'bank_agent'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      🏦 Alert
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setReportTier('ciso')}
                                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 ${
                                        reportTier === 'ciso'
                                          ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                          : 'text-[var(--muted)] hover:text-[var(--text)] border border-transparent'
                                      }`}
                                    >
                                      📋 CISO
                                    </button>
                                  </div>
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

                            <TelemetryStream title="Combined Risk Telemetry Matrix" current={current} />
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
                          {activeRemediation.map((recommendation, i) => (
                            <li key={i} className="text-[15px] pl-3 border-l-2 border-[var(--green)]">
                              {recommendation}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* COLUMN 3: Sticky AI Analyst Sidebar (lg:col-span-3) */}
                  <ChatSidebar
                    chatOpen={chatOpen}
                    setChatOpen={setChatOpen}
                    chatLog={chatLog}
                    chatInput={chatInput}
                    setChatInput={setChatInput}
                    chatBusy={chatBusy}
                    askChat={askChat}
                  />
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
