'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch, fetchSandboxHealth, downloadReport, sendChat, triggerDynamicAnalysis, uploadApkDirect, fetchHistory, printExecutiveReport, getClientSessionId } from '../lib/api';
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
import { RiskBreakdownCard } from '../components/RiskBreakdownCard';

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#10b981',
  LOW: '#10b981',
  MEDIUM: '#f97316',
  HIGH: '#f43f5e',
  CRITICAL: '#f43f5e',
};

const DEMO_RESPONSES = [
  {
    keywords: ['safety', 'safe', 'dangerous', 'harmful', 'trust'],
    text: 'Based on our analysis, this app is NOT safe. It contains signature patterns of mobile banking malware. Running this on a personal device puts your photos, bank accounts, and passwords at risk. We recommend blocking the package immediately.'
  },
  {
    keywords: ['otp', 'sms', 'message', 'intercept', 'hijack'],
    text: 'We detected SMS interceptor capabilities (technique T1603/T1422). The app registers a broadcast receiver that listens for incoming messages, extracts 2FA/OTP numeric codes, and attempts to forward them to an remote server. This is a classic credential-hijacking vector.'
  },
  {
    keywords: ['overlay', 'fake', 'screen', 'draw', 'phish'],
    text: 'The app requests the "Draw over other apps" (overlay) permission. It uses this to render a fake login form on top of legitimate banking applications, tricking users into entering their passwords. This is a severe threat to your digital banking security.'
  },
  {
    keywords: ['remediate', 'fix', 'remove', 'uninstall', 'delete'],
    text: 'To protect yourself: 1) Uninstall this app immediately. 2) Boot your phone into Safe Mode if it resists uninstallation. 3) Change all your banking passwords. 4) Contact your bank to check for unauthorized transactions.'
  },
  {
    keywords: ['rbi', 'guideline', 'compliance', 'ciso'],
    text: 'This app is in direct violation of Section 3.2 of the RBI Digital Payment Security Controls. It lacks secure transportation layers, leaks customer credentials over plain text, and abuses accessibility services. Immediate CISO-level quarantine and blocking are advised.'
  }
];

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
  const [staticTab, setStaticTab] = useState<'manifest' | 'apkid' | 'quark' | 'androguard' | 'secrets' | 'network' | 'compliance' | 'mobsf' | 'virustotal'>('manifest');
  const [storyTab, setStoryTab] = useState<'static' | 'dynamic' | 'final'>('static');
  const [showAdvancedStatic, setShowAdvancedStatic] = useState(false);
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
  const [reportTier, setReportTier] = useState<'soc' | 'bank_agent' | 'ciso'>('soc');

  const [estSecondsRemaining, setEstSecondsRemaining] = useState(30);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [activeReportDialog, setActiveReportDialog] = useState<null | 'reverse_engineering' | 'static_analysis' | 'dynamic_analysis'>(null);


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
    setElapsedSeconds(0);

    try {
      const data = await uploadApkDirect(file, null, getClientSessionId(), setUploadPct);
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
      await triggerDynamicAnalysis(current.id, getClientSessionId());
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
      setElapsedSeconds(0);
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

  const reverseEngSummary = useMemo(() => {
    return current?.investigation_report?.reverse_engineering_summary ?? 
           current?.static_analysis?.investigation_report?.reverse_engineering_summary ?? '';
  }, [current]);

  const staticAnalysisSummary = useMemo(() => {
    return current?.investigation_report?.static_analysis_summary ?? 
           current?.static_analysis?.investigation_report?.static_analysis_summary ?? '';
  }, [current]);

  const dynamicAnalysisSummary = useMemo(() => {
    return current?.investigation_report?.dynamic_analysis_summary ?? 
           current?.static_analysis?.investigation_report?.dynamic_analysis_summary ?? '';
  }, [current]);

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

  const totalSandboxSeconds = useMemo(() => {
    return (isDemo || sandboxOk === false) ? 20 : 120;
  }, [isDemo, sandboxOk]);

  const displayedSecondsRemaining = estSecondsRemaining;

  // Reset estSecondsRemaining to totalSandboxSeconds when dynamic sandbox starts running
  useEffect(() => {
    if (current?.progress?.dynamic_sandbox === 'RUNNING') {
      setEstSecondsRemaining(totalSandboxSeconds);
    }
  }, [current?.progress?.dynamic_sandbox, totalSandboxSeconds]);

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
      setElapsedSeconds((prev) => prev + 1);
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
    return current?.risk_score ?? current?.static_analysis?.risk_score ?? 0;
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
    return (current?.threat_level ?? current?.static_analysis?.threat_level ?? 'SAFE') as ThreatLevel;
  }, [storyTab, current, hasDynamic]);

  const activeAccent = threatColor[activeLevel];

  const activeFraudScore = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.banking_fraud?.fraud_score ?? (hasDynamic ? undefined : current?.banking_fraud?.fraud_score);
    }
    return current?.banking_fraud?.fraud_score ?? current?.static_analysis?.banking_fraud?.fraud_score;
  }, [storyTab, current, hasDynamic]);

  const activeSummaryText = useMemo(() => {
    const ir = storyTab === 'static'
      ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report))
      : (current?.investigation_report ?? current?.static_analysis?.investigation_report);

    let text = '';
    if (storyTab === 'static') {
      text = ir?.summary ?? current?.static_analysis?.investigation_report?.summary ?? (hasDynamic ? '' : current?.investigation_report?.summary ?? current?.investigation_report?.executive_verdict) ?? '';
    } else if (storyTab === 'dynamic') {
      text = ir?.dynamic_summary ?? ir?.summary ?? current?.investigation_report?.summary ?? '';
    } else {
      text = ir?.final_report ?? ir?.summary ?? current?.investigation_report?.summary ?? '';
    }

    if (reportTier === 'bank_agent') {
      return ir?.bank_agent_alert || text;
    }
    if (reportTier === 'ciso') {
      return ir?.ciso_brief || text;
    }
    return text;
  }, [storyTab, reportTier, current, hasDynamic]);

  const activeBadges = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.banking_fraud?.badges ?? (hasDynamic ? [] : current?.banking_fraud?.badges) ?? [];
    }
    return current?.banking_fraud?.badges ?? current?.static_analysis?.banking_fraud?.badges ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeRiskDecomposition = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.risk_decomposition ?? (hasDynamic ? undefined : current?.risk_decomposition);
    }
    return current?.risk_decomposition ?? current?.static_analysis?.risk_decomposition;
  }, [storyTab, current, hasDynamic]);

  const activeAttackTechniques = useMemo(() => {
    if (storyTab === 'static') {
      return current?.static_analysis?.attack_techniques ?? (hasDynamic ? [] : current?.attack_techniques) ?? [];
    }
    return current?.attack_techniques ?? current?.static_analysis?.attack_techniques ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeThreats = useMemo(() => {
    const report = storyTab === 'static'
      ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report))
      : (current?.investigation_report ?? current?.static_analysis?.investigation_report);
    return report?.suspicious_activities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity, evidence_source: a.evidence_source })) ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeVulnerabilities = useMemo(() => {
    const report = storyTab === 'static'
      ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report))
      : (current?.investigation_report ?? current?.static_analysis?.investigation_report);
    return report?.code_vulnerabilities?.map((a) => ({ label: a.title, detail: a.description, severity: a.severity, evidence_source: a.evidence_source })) ?? [];
  }, [storyTab, current, hasDynamic]);

  const activeRemediation = useMemo(() => {
    const report = storyTab === 'static'
      ? (current?.static_analysis?.investigation_report ?? (hasDynamic ? undefined : current?.investigation_report))
      : (current?.investigation_report ?? current?.static_analysis?.investigation_report);
    const fraud = storyTab === 'static'
      ? (current?.static_analysis?.banking_fraud ?? (hasDynamic ? undefined : current?.banking_fraud))
      : (current?.banking_fraud ?? current?.static_analysis?.banking_fraud);
    return [...(report?.recommendations || []), ...(fraud?.recommended_actions || [])];
  }, [storyTab, current, hasDynamic]);

  const staticTelemetryData = useMemo(() => {
    if (!current?.evidence) return null;
    const ev = current.evidence;

    const permissions = ev.permissions || [];
    const exportedComponents = ev.exported_components || [];
    const manifestFlags = ev.dangerous_manifest_flags || [];

    const evasionChecks = ev.malware_rule_hits?.filter(x => x.type === "Anti-VM Check") || [];
    const obfuscationSignals = ev.obfuscation_signals?.filter(x => x.type === "Obfuscator" || x.type === "Packer" || x.type === "Manipulator") || [];

    const apiChains = ev.reflection_dynamic_loading?.filter(x => x.type && x.description?.includes("API chain")) || [];
    const extendedClasses = ev.obfuscation_signals?.filter(x => x.class) || [];
    const bytecodePatterns = ev.suspicious_urls?.filter(x => x.type && !x.url) || [];

    const quarkHits = ev.malware_rule_hits?.filter(x => x.rule && !x.rule.includes("MobSF") && !x.rule.includes("semgrep")) || [];

    const semgrepHits = ev.malware_rule_hits?.filter(x => x.rule?.includes("semgrep")) || [];
    const cryptoSemgrep = ev.crypto_issues?.filter(x => x.type === "semgrep") || [];
    const semgrepViolations = [...semgrepHits, ...cryptoSemgrep];

    const hardcodedSecrets = ev.hardcoded_secrets || [];

    const cleartextUrls = ev.suspicious_urls?.filter(x => x.url) || [];
    const networkConfigIssues = ev.network_indicators?.filter(x => x.source === "xml") || [];
    const networkCodeIssues = ev.network_indicators?.filter(x => x.source === "jadx") || [];

    const mobsfScorecard = ev.mobsf_scorecard || [];
    const virustotal = ev.virustotal;

    return {
      permissions,
      exportedComponents,
      manifestFlags,
      evasionChecks,
      obfuscationSignals,
      apiChains,
      extendedClasses,
      bytecodePatterns,
      quarkHits,
      semgrepViolations,
      hardcodedSecrets,
      cleartextUrls,
      networkConfigIssues,
      networkCodeIssues,
      mobsfScorecard,
      virustotal
    };
  }, [current]);

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
        const lowerMsg = msg.toLowerCase();
        let matchedText = '';
        for (const entry of DEMO_RESPONSES) {
          if (entry.keywords.some(kw => lowerMsg.includes(kw))) {
            matchedText = entry.text;
            break;
          }
        }
        if (!matchedText) {
          matchedText = "Kavach AI analysis is active in sandbox demo mode. The target app shows patterns consistent with the BRATA / banking malware family, including SMS parsing, credential overlays, and insecure cleartext HTTP requests. Let me know if you want to know about overlay risks, SMS theft, or remediation steps!";
        }
        await new Promise(resolve => setTimeout(resolve, 600));
        setChatLog((l) => [...l, { role: 'ai', text: matchedText }]);
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
                <label
                  className="block cursor-pointer group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--blue)] focus-visible:ring-offset-2 focus-visible:ring-offset-black rounded-3xl"
                  tabIndex={0}
                  role="button"
                  aria-label="Upload APK file"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      const input = e.currentTarget.querySelector('input');
                      if (input) {
                        input.click();
                      }
                    }
                  }}
                >
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
                    Est. remaining: <strong className="text-[var(--blue)]">{displayedSecondsRemaining}s</strong> | Elapsed: <strong className="text-[var(--blue)]">{elapsedSeconds}s</strong>
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
                    isAnalyzing={current?.status === 'PROCESSING'}
                  />

                  {/* COLUMN 2: Tabs, Details, Verdicts & Findings (lg:col-span-5 or lg:col-span-8) */}
                  <div className={`space-y-6 transition-all duration-500 ${chatOpen ? 'lg:col-span-6' : 'lg:col-span-8'}`}>
                    {/* Segmented Controller */}
                    <div className="flex justify-center mb-6">
                      <div
                        role="tablist"
                        aria-label="Analysis report tabs"
                        className="inline-flex p-1 rounded-full bg-[var(--surface-2)] border border-[var(--border)] backdrop-blur-md shadow-inner gap-1 relative"
                      >
                        <button
                          type="button"
                          role="tab"
                          aria-selected={storyTab === 'static'}
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
                          role="tab"
                          aria-selected={storyTab === 'dynamic'}
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
                          role="tab"
                          aria-selected={storyTab === 'final'}
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
                        {!showAdvancedStatic ? (
                          <div className="space-y-6 animate-fadeIn">
                            {/* APK Metadata Grid */}
                            <div className="security-card p-6 border border-[var(--border)] relative overflow-hidden bg-[var(--surface)]/40 backdrop-blur-md rounded-3xl">
                              <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-bold mb-4">APK General Overview</p>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4">
                                <div className="space-y-1">
                                  <span className="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">APK Target File</span>
                                  <p className="text-[14px] font-semibold text-zinc-100 truncate">{current.filename || 'Unknown APK'}</p>
                                </div>
                                <div className="space-y-1">
                                  <span className="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Package Identifier</span>
                                  <p className="text-[13px] font-mono text-zinc-300 truncate">{current.package_name || 'N/A'}</p>
                                </div>
                                <div className="space-y-1">
                                  <span className="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Scan Date & Time</span>
                                  <p className="text-[13px] text-zinc-300">
                                    {current.created_at ? new Date(current.created_at).toLocaleString('en-US', {
                                      year: 'numeric',
                                      month: 'short',
                                      day: 'numeric',
                                      hour: '2-digit',
                                      minute: '2-digit'
                                    }) : 'N/A'}
                                  </p>
                                </div>
                                <div className="space-y-1">
                                  <span className="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Submitted By</span>
                                  <p className="text-[13px] text-zinc-300 truncate">{current.email || 'System Forensic Agent'}</p>
                                </div>
                              </div>
                            </div>

                            {/* Threat Level Circle Gauge */}
                            <div className="security-card p-6 border border-[var(--border)] flex flex-col md:flex-row items-center gap-6 bg-[var(--surface)]/40 backdrop-blur-md rounded-3xl">
                              <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
                                <svg className="w-full h-full transform -rotate-90">
                                  <circle
                                    cx="64"
                                    cy="64"
                                    r="52"
                                    stroke="var(--border)"
                                    strokeWidth="8"
                                    fill="transparent"
                                    className="opacity-20"
                                  />
                                  <circle
                                    cx="64"
                                    cy="64"
                                    r="52"
                                    stroke={accent}
                                    strokeWidth="8"
                                    fill="transparent"
                                    strokeDasharray={2 * Math.PI * 52}
                                    strokeDashoffset={2 * Math.PI * 52 * (1 - (current.static_analysis?.risk_score ?? current.risk_score ?? 0) / 100)}
                                    className="transition-all duration-1000 ease-out"
                                  />
                                </svg>
                                <div className="absolute flex flex-col items-center justify-center">
                                  <span className="text-[28px] font-extrabold tracking-tight tabular-nums" style={{ color: accent }}>
                                    {current.static_analysis?.risk_score ?? current.risk_score ?? 0}
                                  </span>
                                  <span className="text-[9px] uppercase tracking-widest text-[var(--muted)] font-bold">Static Risk</span>
                                </div>
                              </div>

                              <div className="space-y-2 flex-1 text-center md:text-left">
                                <div className="flex flex-col md:flex-row items-center gap-3">
                                  <span className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-bold">Heuristic Classification</span>
                                  <span
                                    className="text-[11px] font-extrabold px-3 py-1 rounded-full border shadow-sm transition-all duration-300"
                                    style={{
                                      backgroundColor: `${accent}15`,
                                      borderColor: `${accent}40`,
                                      color: accent
                                    }}
                                  >
                                    {level} RISK VERDICT
                                  </span>
                                </div>
                                <p className="text-[14px] font-medium text-zinc-200">
                                  {level === 'CRITICAL' || level === 'HIGH'
                                    ? 'Severe structural threats, vulnerable extensions, or suspicious API hooks were identified statically.'
                                    : level === 'MEDIUM'
                                    ? 'Moderate risk score. Contains sensitive permission requests and cleartext traffic capabilities.'
                                    : 'Static checks did not identify any immediate dangerous malware indicators or evasion capabilities.'}
                                </p>
                              </div>
                            </div>

                            {/* AI Story Summary Briefing */}
                            {activeSummaryText && (
                              <div className="security-card p-6 space-y-4 border border-[var(--border)] bg-[var(--surface)]/40 backdrop-blur-md rounded-3xl relative overflow-hidden">
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2 border-b border-[var(--border)]/30 pb-3">
                                  <div className="flex items-center gap-2 text-[var(--blue)]">
                                    <span className="text-[16px]">🔎</span>
                                    <span className="text-[12px] uppercase tracking-wider font-bold tracking-widest">Generative AI Forensic Advisory</span>
                                  </div>
                                  <div className="flex bg-[var(--surface-2)]/80 p-0.5 rounded-lg border border-[var(--border)]/30 w-fit gap-1">
                                    {(['soc', 'bank_agent', 'ciso'] as const).map((tier) => (
                                      <button
                                        key={tier}
                                        type="button"
                                        onClick={() => setReportTier(tier)}
                                        className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all duration-200 cursor-pointer border-0 ${
                                          reportTier === tier
                                            ? 'bg-[var(--blue)]/10 text-[var(--blue)] border border-[var(--blue)]/30 shadow-sm'
                                            : 'text-[var(--muted)] hover:text-[var(--text)] bg-transparent'
                                        }`}
                                      >
                                        {tier === 'soc' && '🔧 SOC'}
                                        {tier === 'bank_agent' && '🏦 Alert'}
                                        {tier === 'ciso' && '📋 CISO'}
                                      </button>
                                    ))}
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

                            {/* CTA to Open Advanced Diagnostics */}
                            <div className="text-center pt-2">
                              <button
                                type="button"
                                onClick={() => setShowAdvancedStatic(true)}
                                className="w-full sm:w-auto h-12 px-8 rounded-full bg-[var(--blue)] hover:bg-[var(--blue)]/90 text-white text-[14px] font-semibold cursor-pointer shadow-[0_0_25px_rgba(59,130,246,0.25)] hover:shadow-[0_0_30px_rgba(59,130,246,0.4)] transition-all duration-300 flex items-center justify-center gap-2 mx-auto border-0"
                              >
                                🔍 Enter Advanced Diagnostics Dashboard &rarr;
                              </button>
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-6 animate-fadeIn">
                            {/* Return Navigation */}
                            <div className="flex items-center justify-between border-b border-[var(--border)]/20 pb-4">
                              <div className="flex items-center gap-2">
                                <span className="text-[18px]">⚙️</span>
                                <h3 className="text-[16px] font-extrabold tracking-tight uppercase tracking-wider text-zinc-100">Advanced Diagnostic Vault</h3>
                              </div>
                              <button
                                type="button"
                                onClick={() => setShowAdvancedStatic(false)}
                                className="px-4 py-2 rounded-full border border-[var(--border)] bg-[var(--surface-2)]/50 hover:bg-[var(--border)]/20 text-[12px] font-semibold transition-all duration-200 cursor-pointer text-[var(--text)]"
                              >
                                &larr; Back to Simple Overview
                              </button>
                            </div>

                            {/* 9 Box Interactive Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                              {/* 1. AndroidManifest Inspector */}
                              <StaticToolCard
                                title="AndroidManifest Inspector"
                                icon="📦"
                                statusText={`${staticTelemetryData?.permissions.length} Permissions | ${staticTelemetryData?.exportedComponents.length} Exported | ${staticTelemetryData?.manifestFlags.length} Flags`}
                                statusColor={
                                  staticTelemetryData?.manifestFlags.length || staticTelemetryData?.permissions.filter(p => (p.risk_score ?? 0) >= 10).length
                                    ? 'var(--red)'
                                    : 'var(--green)'
                                }
                                riskScore={Math.max(
                                  ...(staticTelemetryData?.permissions.map(p => p.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.manifestFlags.map(f => f.risk_score ?? 0) || [0])
                                )}
                                isExpanded={!!expandedTools['manifest']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, manifest: !prev.manifest }))}
                              >
                                <div className="space-y-4">
                                  {staticTelemetryData?.permissions && staticTelemetryData.permissions.length > 0 ? (
                                    <div className="space-y-2">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Permissions Requested</p>
                                      {staticTelemetryData.permissions.map((p, i) => (
                                        <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div>
                                            <p className="text-[13px] font-mono text-[var(--text)] break-all">{p.name}</p>
                                            {p.description && <p className="text-[11px] text-[var(--muted)] mt-0.5">{p.description}</p>}
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{p.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <p className="text-[12px] text-[var(--muted)]">No dangerous permissions requested.</p>
                                  )}

                                  {staticTelemetryData?.exportedComponents && staticTelemetryData.exportedComponents.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Exported Components</p>
                                      {staticTelemetryData.exportedComponents.map((ec, i) => (
                                        <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div className="flex justify-between items-start gap-2">
                                            <p className="text-[13px] font-mono break-all font-semibold text-[var(--text)]">{ec.name}</p>
                                            <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-[var(--surface)] text-[var(--muted)] border border-[var(--border)] shrink-0 font-semibold">{ec.type}</span>
                                          </div>
                                          {ec.description && <p className="text-[11px] text-[var(--muted)] mt-1">{ec.description}</p>}
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.manifestFlags && staticTelemetryData.manifestFlags.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Dangerous Flags</p>
                                      {staticTelemetryData.manifestFlags.map((f, i) => (
                                        <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div>
                                            <p className="text-[13px] font-mono font-semibold text-[var(--text)]">{f.flag}</p>
                                            {f.description && <p className="text-[11px] text-[var(--muted)] mt-0.5">{f.description}</p>}
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{f.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 2. APKiD VM Scanner */}
                              <StaticToolCard
                                title="APKiD VM Scanner"
                                icon="🛡"
                                statusText={
                                  staticTelemetryData?.evasionChecks.length || staticTelemetryData?.obfuscationSignals.length
                                    ? `${staticTelemetryData.evasionChecks.length} Evasions | ${staticTelemetryData.obfuscationSignals.length} Obfuscators`
                                    : 'Clean / Standard VM'
                                }
                                statusColor={
                                  staticTelemetryData?.evasionChecks.length
                                    ? 'var(--red)'
                                    : staticTelemetryData?.obfuscationSignals.length
                                    ? 'var(--orange)'
                                    : 'var(--green)'
                                }
                                riskScore={Math.max(
                                  ...(staticTelemetryData?.evasionChecks.map(e => e.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.obfuscationSignals.map(o => o.risk_score ?? 0) || [0])
                                )}
                                isExpanded={!!expandedTools['apkid']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, apkid: !prev.apkid }))}
                              >
                                <div className="space-y-4">
                                  {staticTelemetryData?.evasionChecks && staticTelemetryData.evasionChecks.length > 0 && (
                                    <div className="space-y-2">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Evasion Checks</p>
                                      {staticTelemetryData.evasionChecks.map((a, i) => (
                                        <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div>
                                            <p className="text-[14px] font-semibold">{a.match || "Anti-VM Indicator"}</p>
                                            <p className="text-[11px] text-[var(--muted)] mt-0.5">{a.description}</p>
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)]">+{a.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.obfuscationSignals && staticTelemetryData.obfuscationSignals.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Obfuscation & Packing</p>
                                      {staticTelemetryData.obfuscationSignals.map((o, i) => (
                                        <div key={i} className="flex justify-between items-center py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div>
                                            <p className="text-[14px] font-semibold">{o.match || "Obfuscated Target"}</p>
                                            <p className="text-[11px] text-[var(--muted)] mt-0.5">{o.description}</p>
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)]">+{o.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {(!staticTelemetryData?.evasionChecks.length && !staticTelemetryData?.obfuscationSignals.length) && (
                                    <p className="text-[12px] text-[var(--muted)]">No packer, compiler manipulation, or VM evasion signatures detected.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 3. Androguard DEX Auditor */}
                              <StaticToolCard
                                title="Androguard DEX Auditor"
                                icon="🔍"
                                statusText={
                                  staticTelemetryData?.apiChains.length || staticTelemetryData?.extendedClasses.length || staticTelemetryData?.bytecodePatterns.length
                                    ? `${staticTelemetryData.apiChains.length} API Chains | ${staticTelemetryData.extendedClasses.length} Extended Classes`
                                    : 'Clean Bytecode'
                                }
                                statusColor={
                                  staticTelemetryData?.apiChains.length
                                    ? 'var(--red)'
                                    : staticTelemetryData?.extendedClasses.length
                                    ? 'var(--orange)'
                                    : 'var(--green)'
                                }
                                riskScore={Math.max(
                                  ...(staticTelemetryData?.apiChains.map(c => c.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.extendedClasses.map(e => e.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.bytecodePatterns.map(b => b.risk_score ?? 0) || [0])
                                )}
                                isExpanded={!!expandedTools['androguard']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, androguard: !prev.androguard }))}
                              >
                                <div className="space-y-4">
                                  {staticTelemetryData?.apiChains && staticTelemetryData.apiChains.length > 0 && (
                                    <div className="space-y-2">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">API Call Chains</p>
                                      {staticTelemetryData.apiChains.map((c, i) => (
                                        <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)] flex justify-between items-center gap-3">
                                          <div>
                                            <p className="text-[13px] font-semibold">{c.type}</p>
                                            <p className="text-[11px] text-[var(--muted)] mt-0.5">{c.description}</p>
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.extendedClasses && staticTelemetryData.extendedClasses.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Extended Classes</p>
                                      {staticTelemetryData.extendedClasses.map((s, i) => (
                                        <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div className="flex justify-between items-start gap-2">
                                            <p className="text-[12px] font-mono break-all font-semibold">{s.class}</p>
                                            <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] shrink-0">+{s.risk_score}</span>
                                          </div>
                                          {s.description && <p className="text-[11px] text-[var(--muted)] mt-1">{s.description}</p>}
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.bytecodePatterns && staticTelemetryData.bytecodePatterns.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Bytecode Patterns</p>
                                      {staticTelemetryData.bytecodePatterns.map((str, i) => (
                                        <div key={i} className="py-2.5 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)] flex justify-between items-start gap-3">
                                          <div>
                                            <p className="text-[13px] font-semibold">{str.type}</p>
                                            <p className="text-[11px] font-mono text-[var(--muted)] break-all mt-0.5">{str.value}</p>
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{str.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {(!staticTelemetryData?.apiChains.length && !staticTelemetryData?.extendedClasses.length && !staticTelemetryData?.bytecodePatterns.length) && (
                                    <p className="text-[12px] text-[var(--muted)]">No suspicious static bytecode call chains or patterns matched.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 4. Quark Behavioral Heuristics */}
                              <StaticToolCard
                                title="Quark Behavioral Heuristics"
                                icon="🧠"
                                statusText={
                                  staticTelemetryData?.quarkHits.length
                                    ? `${staticTelemetryData.quarkHits.length} Rules Triggered`
                                    : 'No Behaviors Flagged'
                                }
                                statusColor={staticTelemetryData?.quarkHits.length ? 'var(--red)' : 'var(--green)'}
                                riskScore={Math.max(...(staticTelemetryData?.quarkHits.map(q => q.risk_score ?? 0) || [0]))}
                                isExpanded={!!expandedTools['quark']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, quark: !prev.quark }))}
                              >
                                <div className="space-y-3">
                                  {staticTelemetryData?.quarkHits && staticTelemetryData.quarkHits.length > 0 ? (
                                    staticTelemetryData.quarkHits.map((q, i) => (
                                      <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/30 rounded-2xl border border-[var(--border)] space-y-1.5">
                                        <div className="flex justify-between items-start gap-3">
                                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20 font-semibold">{q.rule}</span>
                                          <span className="text-[11px] px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--muted)] font-medium">
                                            Confidence: {q.confidence || '100%'}
                                          </span>
                                        </div>
                                        <p className="text-[13px] font-semibold leading-snug">{q.description}</p>
                                        <div className="flex justify-between items-center text-[11px] text-[var(--muted)] pt-1 border-t border-[var(--border)]/30">
                                          <span>Severity: {q.severity || 'HIGH'}</span>
                                          <span className="text-[var(--red)] font-semibold">+{q.risk_score} pts</span>
                                        </div>
                                      </div>
                                    ))
                                  ) : (
                                    <p className="text-[12px] text-[var(--muted)]">No Quark behavioral rules triggered.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 5. Semgrep AST Compliance */}
                              <StaticToolCard
                                title="Semgrep AST Compliance"
                                icon="🚨"
                                statusText={
                                  staticTelemetryData?.semgrepViolations.length
                                    ? `${staticTelemetryData.semgrepViolations.length} Violations Found`
                                    : 'Compliant / Clean'
                                }
                                statusColor={staticTelemetryData?.semgrepViolations.length ? 'var(--red)' : 'var(--green)'}
                                riskScore={Math.max(...(staticTelemetryData?.semgrepViolations.map(s => s.risk_score ?? 10) || [0]))}
                                isExpanded={!!expandedTools['compliance']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, compliance: !prev.compliance }))}
                              >
                                <div className="space-y-3">
                                  {staticTelemetryData?.semgrepViolations && staticTelemetryData.semgrepViolations.length > 0 ? (
                                    staticTelemetryData.semgrepViolations.map((s, i) => (
                                      <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/30 rounded-2xl border border-[var(--border)] space-y-1.5">
                                        <div className="flex justify-between items-start gap-3">
                                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--red)]/15 text-[var(--red)] font-bold border border-[var(--red)]/20 shrink-0">{s.severity || "HIGH"}</span>
                                          <span className="text-[12px] font-semibold text-[var(--red)]">+{s.risk_score || 10} pts</span>
                                        </div>
                                        <p className="text-[13px] font-semibold">{s.description || s.rule}</p>
                                        {s.file && <p className="text-[10px] font-mono text-[var(--muted)] break-all bg-[var(--surface)] py-1 px-2 rounded">{s.file}</p>}
                                      </div>
                                    ))
                                  ) : (
                                    <p className="text-[12px] text-[var(--muted)]">No Semgrep AST compliance violations found.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 6. Deep Secrets Scanner */}
                              <StaticToolCard
                                title="Deep Secrets Scanner"
                                icon="🔑"
                                statusText={
                                  staticTelemetryData?.hardcodedSecrets.length
                                    ? `${staticTelemetryData.hardcodedSecrets.length} Leaks Detected`
                                    : 'Clean / No Leaks'
                                }
                                statusColor={staticTelemetryData?.hardcodedSecrets.length ? 'var(--red)' : 'var(--green)'}
                                riskScore={Math.max(...(staticTelemetryData?.hardcodedSecrets.map(s => s.risk_score ?? 0) || [0]))}
                                isExpanded={!!expandedTools['secrets']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, secrets: !prev.secrets }))}
                              >
                                <div className="space-y-3">
                                  {staticTelemetryData?.hardcodedSecrets && staticTelemetryData.hardcodedSecrets.length > 0 ? (
                                    staticTelemetryData.hardcodedSecrets.map((s, i) => (
                                      <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/30 rounded-2xl border border-[var(--border)] space-y-1.5">
                                        <div className="flex justify-between items-start gap-3">
                                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--red)]/15 text-[var(--red)] font-bold border border-[var(--red)]/20">{s.severity}</span>
                                          <span className="text-[12px] font-semibold text-[var(--red)]">+{s.risk_score} pts</span>
                                        </div>
                                        <p className="text-[14px] font-semibold">{s.type}</p>
                                        {s.file && <p className="text-[10px] font-mono text-[var(--muted)] break-all bg-[var(--surface)] py-1 px-2 rounded">{s.file}</p>}
                                        <p className="text-[13px] text-[var(--muted)] pt-0.5 leading-relaxed">{s.description}</p>
                                      </div>
                                    ))
                                  ) : (
                                    <p className="text-[12px] text-[var(--muted)]">No credentials, keys, or hardcoded tokens leaked.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 7. Network Config & HTTP Auditor */}
                              <StaticToolCard
                                title="Network Config Auditor"
                                icon="🌐"
                                statusText={
                                  staticTelemetryData?.cleartextUrls.length || staticTelemetryData?.networkConfigIssues.length || staticTelemetryData?.networkCodeIssues.length
                                    ? `${staticTelemetryData.cleartextUrls.length} HTTP URLs | ${staticTelemetryData.networkConfigIssues.length + staticTelemetryData.networkCodeIssues.length} Config Issues`
                                    : 'Secure TLS only'
                                }
                                statusColor={
                                  staticTelemetryData?.cleartextUrls.length || staticTelemetryData?.networkConfigIssues.length || staticTelemetryData?.networkCodeIssues.length
                                    ? 'var(--red)'
                                    : 'var(--green)'
                                }
                                riskScore={Math.max(
                                  ...(staticTelemetryData?.cleartextUrls.map(u => u.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.networkConfigIssues.map(c => c.risk_score ?? 0) || [0]),
                                  ...(staticTelemetryData?.networkCodeIssues.map(c => c.risk_score ?? 0) || [0])
                                )}
                                isExpanded={!!expandedTools['network']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, network: !prev.network }))}
                              >
                                <div className="space-y-4">
                                  {staticTelemetryData?.networkConfigIssues && staticTelemetryData.networkConfigIssues.length > 0 && (
                                    <div className="space-y-2">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Network Security Config (XML)</p>
                                      {staticTelemetryData.networkConfigIssues.map((c, i) => (
                                        <div key={i} className="py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)] flex justify-between items-center gap-3">
                                          <div>
                                            <p className="text-[13px] font-semibold">{c.type}</p>
                                            <p className="text-[11px] text-[var(--muted)] mt-0.5">{c.description}</p>
                                          </div>
                                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.networkCodeIssues && staticTelemetryData.networkCodeIssues.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Cleartext Protocols in Code</p>
                                      {staticTelemetryData.networkCodeIssues.map((c, i) => (
                                        <div key={i} className="py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                          <div className="flex justify-between items-center gap-3">
                                            <p className="text-[13px] font-semibold">{c.type}</p>
                                            <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-[var(--red)]/10 text-[var(--red)] shrink-0">+{c.risk_score}</span>
                                          </div>
                                          {c.file && <p className="text-[10px] font-mono text-[var(--muted)] break-all mt-1 bg-[var(--surface)] py-0.5 px-1.5 rounded inline-block">{c.file}</p>}
                                        </div>
                                      ))}
                                    </div>
                                  )}

                                  {staticTelemetryData?.cleartextUrls && staticTelemetryData.cleartextUrls.length > 0 && (
                                    <div className="space-y-2 border-t border-[var(--border)]/30 pt-3">
                                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold">Suspicious / HTTP Endpoint URLs</p>
                                      <div className="max-h-60 overflow-y-auto space-y-2 pr-1">
                                        {staticTelemetryData.cleartextUrls.map((url, i) => (
                                          <div key={i} className="py-2 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)]">
                                            <p className="text-[12px] font-mono break-all text-[var(--text)] font-semibold">{url.url}</p>
                                            {url.file && <p className="text-[10px] font-mono text-[var(--muted)] break-all mt-1 bg-[var(--surface)] py-0.5 px-1.5 rounded inline-block">{url.file}</p>}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {(!staticTelemetryData?.cleartextUrls.length && !staticTelemetryData?.networkConfigIssues.length && !staticTelemetryData?.networkCodeIssues.length) && (
                                    <p className="text-[12px] text-[var(--muted)]">No cleartext HTTP permissions or domain indicators reported.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 8. MobSF Scorecard */}
                              <StaticToolCard
                                title="MobSF Scorecard"
                                icon="📈"
                                statusText={
                                  staticTelemetryData?.mobsfScorecard.length
                                    ? `${staticTelemetryData.mobsfScorecard.length} Warnings Reported`
                                    : 'Clean Scorecard'
                                }
                                statusColor={staticTelemetryData?.mobsfScorecard.length ? 'var(--red)' : 'var(--green)'}
                                riskScore={staticTelemetryData?.mobsfScorecard.length ? 30 : 0}
                                isExpanded={!!expandedTools['mobsf']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, mobsf: !prev.mobsf }))}
                              >
                                <div className="space-y-3">
                                  {staticTelemetryData?.mobsfScorecard && staticTelemetryData.mobsfScorecard.length > 0 ? (
                                    staticTelemetryData.mobsfScorecard.map((item, i) => (
                                      <div key={i} className="py-3 px-4 bg-[var(--surface-2)]/30 rounded-2xl border border-[var(--border)] space-y-1">
                                        <div className="flex justify-between items-start gap-2">
                                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-[var(--border)] text-[var(--muted)] font-semibold">{item.severity || 'INFO'}</span>
                                          <span className="text-[11px] font-semibold text-[var(--muted)]">{item.type || 'MobSF'}</span>
                                        </div>
                                        <p className="text-[13px] font-semibold leading-relaxed mt-1 text-zinc-100">{item.title}</p>
                                        {item.description && <p className="text-[12px] text-[var(--muted)] leading-relaxed mt-0.5">{item.description}</p>}
                                      </div>
                                    ))
                                  ) : (
                                    <p className="text-[12px] text-[var(--muted)]">No MobSF scorecard warnings reported.</p>
                                  )}
                                </div>
                              </StaticToolCard>

                              {/* 9. VirusTotal Threat Intel */}
                              <StaticToolCard
                                title="VirusTotal Threat Intel"
                                icon="🛡"
                                statusText={
                                  staticTelemetryData?.virustotal?.status === 'success'
                                    ? `${staticTelemetryData.virustotal.malicious}/${staticTelemetryData.virustotal.total} Engines Malicious`
                                    : staticTelemetryData?.virustotal?.status === 'skipped'
                                    ? 'API Key Missing'
                                    : 'Not Indexed / Pending'
                                }
                                statusColor={
                                  staticTelemetryData?.virustotal?.malicious
                                    ? 'var(--red)'
                                    : staticTelemetryData?.virustotal?.status === 'success'
                                    ? 'var(--green)'
                                    : 'var(--muted)'
                                }
                                riskScore={staticTelemetryData?.virustotal?.malicious ? staticTelemetryData.virustotal.malicious * 10 : 0}
                                isExpanded={!!expandedTools['virustotal']}
                                onToggle={() => setExpandedTools(prev => ({ ...prev, virustotal: !prev.virustotal }))}
                              >
                                {(() => {
                                  const vt = staticTelemetryData?.virustotal;
                                  if (!vt || vt.status === 'skipped') {
                                    return <p className="text-[12px] text-[var(--muted)]">VirusTotal integration requires a <code className="bg-[var(--surface)] px-1 rounded">VIRUSTOTAL_API_KEY</code> env variable. Set it in your backend <code>.env</code> file.</p>;
                                  }
                                  if (vt.status === 'not_found') {
                                    return (
                                      <div className="py-2.5 px-3 bg-[var(--surface-2)]/40 rounded-xl border border-[var(--border)] space-y-1">
                                        <p className="text-[13px] font-semibold text-[var(--muted)]">File not previously indexed</p>
                                        <p className="text-[12px] text-[var(--muted)]">This APK has not been scanned by VirusTotal before. It may be a novel or private sample.</p>
                                      </div>
                                    );
                                  }
                                  if (vt.status === 'rate_limited') {
                                    return <p className="text-[12px] text-[var(--red)]">VirusTotal free tier rate limit hit (4 req/min). Try again shortly.</p>;
                                  }
                                  if (vt.status === 'success') {
                                    const malicious = vt.malicious || 0;
                                    const undetected = vt.undetected || 0;
                                    const total = vt.total || 0;
                                    const permalink = vt.permalink || '#';
                                    return (
                                      <div className="space-y-4">
                                        <div className="grid grid-cols-3 gap-3">
                                          <div className={`py-3 px-2 rounded-xl border text-center space-y-0.5 ${ malicious > 0 ? 'bg-[var(--red)]/10 border-[var(--red)]/30' : 'bg-[var(--green)]/10 border-[var(--green)]/30'}`}>
                                            <p className={`text-[20px] font-bold tabular-nums ${ malicious > 0 ? 'text-[var(--red)]' : 'text-[var(--green)]'}`}>{malicious}</p>
                                            <p className="text-[9px] text-[var(--muted)] uppercase tracking-wider font-bold">Malicious</p>
                                          </div>
                                          <div className="py-3 px-2 rounded-xl border border-[var(--border)] bg-[var(--surface-2)]/40 text-center space-y-0.5">
                                            <p className="text-[20px] font-bold tabular-nums text-[var(--muted)]">{undetected}</p>
                                            <p className="text-[9px] text-[var(--muted)] uppercase tracking-wider font-bold">Clean</p>
                                          </div>
                                          <div className="py-3 px-2 rounded-xl border border-[var(--border)] bg-[var(--surface-2)]/40 text-center space-y-0.5">
                                            <p className="text-[20px] font-bold tabular-nums text-zinc-300">{total}</p>
                                            <p className="text-[9px] text-[var(--muted)] uppercase tracking-wider font-bold">Total</p>
                                          </div>
                                        </div>
                                        {malicious > 0 && (
                                          <div className="py-2 px-3 rounded-lg bg-[var(--red)]/10 border border-[var(--red)]/20">
                                            <p className="text-[12px] text-[var(--red)]">⚠ {malicious} of {total} antivirus engines flagged this file as malicious.</p>
                                          </div>
                                        )}
                                        {permalink && permalink !== '#' && (
                                          <a href={permalink} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 text-[12px] text-[var(--blue)] hover:underline">
                                            View full VirusTotal report &rarr;
                                          </a>
                                        )}
                                      </div>
                                    );
                                  }
                                  return <p className="text-[12px] text-[var(--muted)]">VT scan status: {vt?.status || 'unknown'}. {vt?.reason || ''}</p>;
                                })()}
                              </StaticToolCard>
                            </div>
                          </div>
                        )}

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
                              <span className="text-[11px] font-mono text-[var(--muted)] animate-pulse">Est. remaining: {estSecondsRemaining}s | Elapsed: {elapsedSeconds}s</span>
                            </div>
                            <div className="space-y-3">
                              <p className="text-[15px] font-semibold">Dynamic Instrumentation Tracing</p>
                              <p className="text-[13px] text-[var(--muted)] leading-relaxed">
                                Booting Android sandbox, preparing Frida hook packs, and initiating UI triggers. Telemetry signals are recorded in real-time.
                              </p>
                              <div className="relative h-2 w-full rounded-full bg-[var(--surface-2)] overflow-hidden border border-[var(--border)]">
                                <div className="h-full bg-[var(--blue)] animate-pulse rounded-full transition-all duration-1000 ease-linear" style={{ width: `${Math.min(100, Math.max(0, Math.round(((totalSandboxSeconds - estSecondsRemaining) / totalSandboxSeconds) * 100)))}%` }} />
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

                            <RiskBreakdownCard
                              title="Risk Breakdown"
                              riskDecomposition={activeRiskDecomposition}
                              accent={accent}
                              excludeKey="static"
                            />

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
                            {/* 3-PILLAR HACKATHON DASHBOARD LAYOUT */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                              {/* Left Panel: Reverse Engineering */}
                              <div
                                onClick={() => setActiveReportDialog('reverse_engineering')}
                                className="security-card p-6 border border-emerald-500/20 hover:border-emerald-500/40 transition-all duration-300 shadow-[0_0_15px_rgba(16,185,129,0.02)] hover:shadow-[0_0_20px_rgba(16,185,129,0.08)] cursor-pointer group flex flex-col justify-between min-h-[220px]"
                              >
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between border-b border-[var(--border)]/30 pb-2">
                                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-[13px] uppercase tracking-wider">
                                      <span>⚙️</span>
                                      <span>Reverse Engineering</span>
                                    </div>
                                    <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded-full font-bold">GenAI</span>
                                  </div>
                                  <div className="text-[13.5px] leading-relaxed text-[var(--muted)] line-clamp-[6] overflow-hidden">
                                    {reverseEngSummary || "No reverse engineering narrative compiled yet. Run deep scan analysis to generate AI insights."}
                                  </div>
                                </div>
                                <span className="text-[12px] text-emerald-400 font-bold mt-4 block group-hover:underline">
                                  Read Full Analysis &rarr;
                                </span>
                              </div>

                              {/* Middle Panel: Static Analysis */}
                              <div
                                onClick={() => setActiveReportDialog('static_analysis')}
                                className="security-card p-6 border border-sky-500/20 hover:border-sky-500/40 transition-all duration-300 shadow-[0_0_15px_rgba(56,189,248,0.02)] hover:shadow-[0_0_20px_rgba(56,189,248,0.08)] cursor-pointer group flex flex-col justify-between min-h-[220px]"
                              >
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between border-b border-[var(--border)]/30 pb-2">
                                    <div className="flex items-center gap-2 text-sky-400 font-bold text-[13px] uppercase tracking-wider">
                                      <span>🔍</span>
                                      <span>Static Analysis</span>
                                    </div>
                                    <span className="text-[10px] bg-sky-500/10 text-sky-400 px-2 py-0.5 rounded-full font-bold">GenAI</span>
                                  </div>
                                  <div className="text-[13.5px] leading-relaxed text-[var(--muted)] line-clamp-[6] overflow-hidden">
                                    {staticAnalysisSummary || "No static analysis narrative compiled yet. Run deep scan analysis to generate AI insights."}
                                  </div>
                                </div>
                                <span className="text-[12px] text-sky-400 font-bold mt-4 block group-hover:underline">
                                  Read Full Analysis &rarr;
                                </span>
                              </div>

                              {/* Right Panel: Dynamic Analysis */}
                              <div
                                onClick={() => setActiveReportDialog('dynamic_analysis')}
                                className="security-card p-6 border border-indigo-500/20 hover:border-indigo-500/40 transition-all duration-300 shadow-[0_0_15px_rgba(99,102,241,0.02)] hover:shadow-[0_0_20px_rgba(99,102,241,0.08)] cursor-pointer group flex flex-col justify-between min-h-[220px]"
                              >
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between border-b border-[var(--border)]/30 pb-2">
                                    <div className="flex items-center gap-2 text-indigo-400 font-bold text-[13px] uppercase tracking-wider">
                                      <span>⚡</span>
                                      <span>Dynamic Analysis</span>
                                    </div>
                                    <span className="text-[10px] bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded-full font-bold">GenAI</span>
                                  </div>
                                  <div className="text-[13.5px] leading-relaxed text-[var(--muted)] line-clamp-[6] overflow-hidden">
                                    {dynamicAnalysisSummary || "No dynamic sandbox narrative compiled yet. Run deep scan analysis to generate AI insights."}
                                  </div>
                                </div>
                                <span className="text-[12px] text-indigo-400 font-bold mt-4 block group-hover:underline">
                                  Read Full Analysis &rarr;
                                </span>
                              </div>
                            </div>

                            <RiskBreakdownCard
                              title="Overall Risk Breakdown"
                              riskDecomposition={activeRiskDecomposition}
                              accent={accent}
                            />

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

      {/* FULL-SCREEN AI PILLAR ADVISORY DIALOG */}
      <AnimatePresence>
        {activeReportDialog && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center p-4 md:p-6"
            onClick={() => setActiveReportDialog(null)}
          >
            <motion.div
              initial={{ scale: 0.95, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.95, y: 20 }}
              className="bg-[#0B0B14] border border-[var(--border)] rounded-[2.5rem] w-full max-w-4xl max-h-[85vh] overflow-hidden shadow-[0_0_50px_rgba(59,130,246,0.15)] flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="px-8 py-6 border-b border-[var(--border)]/30 flex items-center justify-between bg-[var(--surface)]/30 backdrop-blur-sm">
                <div className="flex items-center gap-3">
                  <span className="text-[20px]">
                    {activeReportDialog === 'reverse_engineering' ? '⚙️' : activeReportDialog === 'static_analysis' ? '🔍' : '⚡'}
                  </span>
                  <div>
                    <h2 className="text-[18px] font-bold text-[#FFFFFF] tracking-tight uppercase tracking-wider">
                      {activeReportDialog === 'reverse_engineering' ? 'Reverse Engineering Insights' : activeReportDialog === 'static_analysis' ? 'Static Analysis Audit' : 'Dynamic Behavior Trace'}
                    </h2>
                    <p className="text-[11px] text-[var(--muted)] font-medium mt-0.5">
                      AUTOMATED GENERATIVE AI INTEL GATEWAY SUMMARY
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setActiveReportDialog(null)}
                  className="w-10 h-10 rounded-full bg-[var(--surface-2)] border border-[var(--border)]/50 hover:bg-[var(--border)]/20 transition-all duration-200 flex items-center justify-center cursor-pointer text-[#FFFFFF] font-bold text-[18px] border-0"
                >
                  &times;
                </button>
              </div>

              {/* Scrollable Content */}
              <div className="p-8 overflow-y-auto space-y-6 flex-1 text-left custom-scrollbar">
                <div className="p-6 rounded-2xl bg-zinc-950/40 border border-[var(--border)]/30 min-h-[250px] leading-relaxed">
                  <MarkdownBody
                    text={
                      activeReportDialog === 'reverse_engineering'
                        ? reverseEngSummary || "No reverse engineering data found. Run a deep static analysis to populate."
                        : activeReportDialog === 'static_analysis'
                        ? staticAnalysisSummary || "No static analysis data found. Run a deep static analysis to populate."
                        : dynamicAnalysisSummary || "No dynamic sandbox data found. Run dynamic sandbox analysis to populate."
                    }
                  />
                </div>
              </div>

              {/* Footer */}
              <div className="px-8 py-5 border-t border-[var(--border)]/30 bg-[var(--surface)]/10 text-right">
                <button
                  onClick={() => setActiveReportDialog(null)}
                  className="px-6 py-2.5 rounded-full bg-[var(--blue)] text-white hover:bg-[var(--blue)]/90 transition-all duration-200 font-semibold text-[13px] border-0 cursor-pointer shadow-[0_0_15px_rgba(59,130,246,0.3)]"
                >
                  Done / Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

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

function FindingsBlock({ title, items }: { title: string; items?: { label: string; detail?: string; severity?: string; evidence_source?: string }[] }) {
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
                <div className="flex items-center gap-1.5 shrink-0">
                  {item.evidence_source === 'confirmed' && (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-[#10b981]/10 text-[#10b981]">
                      ✓ Evidence-Backed
                    </span>
                  )}
                  {item.evidence_source === 'ai_only' && (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-[#eab308]/10 text-[#eab308]">
                      ⚠ AI Inferred
                    </span>
                  )}
                  {sev && SEVERITY_COLORS[sev] && (
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${colors.bg} ${colors.text}`}>{sev}</span>
                  )}
                </div>
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

interface StaticToolCardProps {
  title: string;
  icon: string;
  statusText: string;
  statusColor: string;
  riskScore: number;
  isExpanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}

function StaticToolCard({
  title,
  icon,
  statusText,
  statusColor,
  riskScore,
  isExpanded,
  onToggle,
  children
}: StaticToolCardProps) {
  return (
    <div
      onClick={onToggle}
      className={`security-card border border-[var(--border)] bg-[var(--surface-2)]/30 backdrop-blur-md rounded-3xl p-5 transition-all duration-300 hover:border-[var(--border-hover)] hover:bg-[var(--surface-2)]/40 hover:shadow-[0_0_20px_rgba(59,130,246,0.04)] flex flex-col gap-3 cursor-pointer ${
        isExpanded ? 'border-[var(--blue)]/40 shadow-[0_0_15px_rgba(59,130,246,0.06)]' : ''
      }`}
    >
      {/* Top Header Row */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="text-[18px]">{icon}</span>
          <h4 className="text-[14.5px] font-bold text-zinc-100 tracking-tight">{title}</h4>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {riskScore > 0 && (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[var(--red)]/10 text-[var(--red)] border border-[var(--red)]/20 shadow-sm">
              +{riskScore} pts
            </span>
          )}
          <span
            className="w-2.5 h-2.5 rounded-full"
            style={{ backgroundColor: statusColor }}
            title={`Status: ${statusText}`}
          />
        </div>
      </div>

      {/* Summary Line */}
      <p className="text-[12px] text-[var(--muted)] font-medium leading-normal truncate">
        {statusText}
      </p>

      {/* Click instructions or open indicator */}
      <div className="flex items-center justify-between text-[11px] text-[var(--muted)] font-semibold border-t border-[var(--border)]/25 pt-2 mt-1">
        <span>{isExpanded ? 'Click to collapse' : 'Click to inspect details'}</span>
        <span className="text-[12px]">{isExpanded ? '↑' : '↓'}</span>
      </div>

      {/* Detail Pane */}
      {isExpanded && (
        <div
          onClick={(e) => e.stopPropagation()}
          className="border-t border-[var(--border)]/30 pt-4 mt-2 text-left space-y-3 cursor-default animate-fadeIn"
        >
          {children}
        </div>
      )}
    </div>
  );
}
