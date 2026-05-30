'use client';

import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from 'firebase/auth';
import {
  ref,
  uploadBytesResumable,
  getDownloadURL,
} from 'firebase/storage';
import {
  collection,
  doc,
  onSnapshot,
  query,
  where,
  orderBy,
} from 'firebase/firestore';
import { auth, googleProvider, storage, db } from '../lib/firebase';
import type { AnalysisDoc, ThreatLevel } from '../lib/types';

const API = (process.env.NEXT_PUBLIC_API_BASE_URL || '').replace(/\/$/, '');

const threatColor: Record<ThreatLevel, string> = {
  SAFE: '#81c995',
  LOW: '#81c995',
  MEDIUM: '#fdd663',
  HIGH: '#f28b82',
  CRITICAL: '#ea4335',
};

function formatDate(v?: string) {
  if (!v) return '';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function activeStep(progress?: Record<string, string>) {
  if (!progress) return 'Starting';
  const running = Object.entries(progress).find(([, s]) => s === 'RUNNING');
  if (running) return running[0].replace(/_/g, ' ');
  const waiting = Object.entries(progress).find(([, s]) => s === 'WAITING');
  if (waiting) return waiting[0].replace(/_/g, ' ');
  return 'Finalizing';
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [history, setHistory] = useState<AnalysisDoc[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [active, setActive] = useState<AnalysisDoc | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploadPct, setUploadPct] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    return onAuthStateChanged(auth, (u) => {
      setUser(u);
      setAuthReady(true);
    });
  }, []);

  useEffect(() => {
    if (!user) return;
    const q = query(
      collection(db, 'apkanalysisresults'),
      where('uid', '==', user.uid),
      orderBy('created_at', 'desc')
    );
    return onSnapshot(q, (snap) => {
      setHistory(snap.docs.map((d) => ({ id: d.id, ...d.data() } as AnalysisDoc)));
    });
  }, [user]);

  useEffect(() => {
    if (!activeId) return;
    return onSnapshot(doc(db, 'apkanalysisresults', activeId), (snap) => {
      if (snap.exists()) setActive({ id: snap.id, ...snap.data() } as AnalysisDoc);
    });
  }, [activeId]);

  const signIn = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch {
      setError('Sign-in failed.');
    }
  };

  const analyze = async () => {
    if (!file || !user || busy) return;
    setError(null);
    setBusy(true);
    setUploadPct(0);
    setActiveId(null);

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

      const res = await fetch(`${API}/api/analyze?background=true`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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

  const displayHistory = user ? history : [];
  const current = activeId ? active : null;

  const view = useMemo(() => {
    if (!user) return 'auth';
    if (current?.status === 'PROCESSING' || busy) return 'scan';
    if (current?.status === 'COMPLETED' || current?.status === 'FAILED') return 'result';
    return 'home';
  }, [user, current, busy]);

  const score = current?.risk_score ?? 0;
  const level = (current?.threat_level ?? 'SAFE') as ThreatLevel;
  const accent = threatColor[level];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-5 max-w-5xl mx-auto w-full">
        <button
          type="button"
          onClick={() => { setActiveId(null); setActive(null); setFile(null); }}
          className="text-[15px] font-semibold tracking-tight text-[var(--text)] bg-transparent border-0 cursor-pointer"
        >
          Kavach
        </button>
        {user ? (
          <button
            type="button"
            onClick={() => signOut(auth)}
            className="text-[13px] text-[var(--muted)] hover:text-[var(--text)] transition-colors bg-transparent border-0 cursor-pointer"
          >
            Sign out
          </button>
        ) : null}
      </header>

      <main className="flex-1 flex flex-col items-center justify-center px-6 pb-16 max-w-2xl mx-auto w-full">
        <AnimatePresence mode="wait">
          {/* Auth */}
          {view === 'auth' && authReady && (
            <motion.div
              key="auth"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="text-center space-y-8 w-full"
            >
              <div className="space-y-3">
                <h1 className="text-[40px] sm:text-[48px] font-semibold tracking-tight leading-[1.1]">
                  Fraud APK analysis
                </h1>
                <p className="text-[17px] text-[var(--muted)] max-w-md mx-auto leading-relaxed">
                  Upload a suspicious Android app. Get a risk score and AI verdict in minutes.
                </p>
              </div>
              <button
                type="button"
                onClick={signIn}
                className="inline-flex items-center gap-2 h-12 px-8 rounded-full bg-[var(--text)] text-[var(--bg)] text-[15px] font-medium cursor-pointer border-0 hover:opacity-90 transition-opacity"
              >
                Continue with Google
              </button>
            </motion.div>
          )}

          {/* Home / Upload */}
          {view === 'home' && (
            <motion.div
              key="home"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="w-full space-y-10"
            >
              <div className="text-center space-y-2">
                <h1 className="text-[32px] sm:text-[40px] font-semibold tracking-tight">Analyze an APK</h1>
                <p className="text-[15px] text-[var(--muted)]">Drop a file or browse</p>
              </div>

              <label className="block cursor-pointer group">
                <input
                  type="file"
                  accept=".apk"
                  className="sr-only"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f?.name.endsWith('.apk')) { setFile(f); setError(null); }
                    else setError('APK files only.');
                  }}
                />
                <div className="rounded-3xl border border-dashed border-[var(--border)] bg-[var(--surface)] px-8 py-16 text-center transition-colors group-hover:border-[rgba(138,180,248,0.4)] group-hover:bg-[var(--surface-2)]">
                  <p className="text-[17px] font-medium">{file ? file.name : 'Select .apk'}</p>
                  {file ? (
                    <p className="text-[13px] text-[var(--muted)] mt-2">{(file.size / 1048576).toFixed(1)} MB</p>
                  ) : null}
                </div>
              </label>

              {error ? <p className="text-[14px] text-[var(--red)] text-center">{error}</p> : null}

              {file ? (
                <button
                  type="button"
                  onClick={analyze}
                  disabled={busy}
                  className="w-full h-12 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[15px] font-semibold border-0 cursor-pointer disabled:opacity-50"
                >
                  Run analysis
                </button>
              ) : null}

              {displayHistory.length > 0 ? (
                <div className="space-y-3 pt-4">
                  <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Recent</p>
                  <ul className="space-y-1">
                    {displayHistory.slice(0, 6).map((item) => (
                      <li key={item.id}>
                        <button
                          type="button"
                          onClick={() => setActiveId(item.id)}
                          className="w-full flex items-center justify-between gap-4 py-3 px-4 rounded-2xl bg-transparent hover:bg-[var(--surface)] border-0 cursor-pointer text-left transition-colors"
                        >
                          <span className="text-[15px] truncate">{item.filename || 'Unknown'}</span>
                          <span className="text-[13px] text-[var(--muted)] shrink-0 tabular-nums">
                            {item.risk_score ?? '—'} · {formatDate(item.created_at)}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </motion.div>
          )}

          {/* Scanning */}
          {view === 'scan' && (
            <motion.div
              key="scan"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center space-y-8 w-full"
            >
              <div className="relative w-32 h-32 mx-auto">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="44" fill="none" stroke="var(--surface-2)" strokeWidth="4" />
                  <circle
                    cx="50"
                    cy="50"
                    r="44"
                    fill="none"
                    stroke="var(--blue)"
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeDasharray={`${busy ? uploadPct * 2.76 : 50} 276`}
                    className="transition-all duration-300"
                  />
                </svg>
                <span className="absolute inset-0 flex items-center justify-center text-[24px] font-semibold tabular-nums">
                  {busy ? `${uploadPct}%` : '···'}
                </span>
              </div>
              <div>
                <p className="text-[20px] font-medium">{busy ? 'Uploading' : 'Analyzing'}</p>
                <p className="text-[15px] text-[var(--muted)] mt-2 capitalize">
                  {busy ? file?.name : activeStep(current?.progress)}
                </p>
              </div>
            </motion.div>
          )}

          {/* Result */}
          {view === 'result' && current && (
            <motion.div
              key="result"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="w-full space-y-10"
            >
              {current.status === 'FAILED' ? (
                <div className="text-center space-y-4">
                  <p className="text-[48px] font-semibold text-[var(--red)]">Failed</p>
                  <p className="text-[15px] text-[var(--muted)]">{current.error_message || 'Analysis could not complete.'}</p>
                </div>
              ) : (
                <>
                  <div className="text-center space-y-4">
                    <p
                      className="text-[72px] sm:text-[88px] font-semibold tabular-nums leading-none tracking-tight"
                      style={{ color: accent }}
                    >
                      {score}
                    </p>
                    <p className="text-[13px] uppercase tracking-[0.2em] font-medium" style={{ color: accent }}>
                      {level} risk
                    </p>
                    <p className="text-[15px] text-[var(--muted)]">{current.filename}</p>
                  </div>

                  {(current.investigation_report?.executive_verdict || current.investigation_report?.summary) && (
                    <div className="rounded-3xl bg-[var(--surface)] p-6 sm:p-8">
                      <p className="text-[17px] leading-relaxed text-[var(--text)]">
                        {current.investigation_report.executive_verdict || current.investigation_report.summary}
                      </p>
                    </div>
                  )}

                  <FindingsBlock
                    title="Threats"
                    items={current.investigation_report?.suspicious_activities?.map((a) => ({
                      label: a.title,
                      detail: a.description,
                    }))}
                  />

                  <FindingsBlock
                    title="Vulnerabilities"
                    items={current.investigation_report?.code_vulnerabilities?.map((a) => ({
                      label: a.title,
                      detail: a.description,
                    }))}
                  />

                  {current.evidence?.dynamic_analysis?.runtime_findings &&
                  current.evidence.dynamic_analysis.runtime_findings.length > 0 ? (
                    <FindingsBlock
                      title="Runtime"
                      items={current.evidence.dynamic_analysis.runtime_findings.map((f) => ({
                        label: f.title || 'Finding',
                        detail: f.summary,
                      }))}
                    />
                  ) : null}

                  {current.investigation_report?.recommendations &&
                  current.investigation_report.recommendations.length > 0 ? (
                    <div className="rounded-3xl bg-[var(--surface)] p-6 sm:p-8 space-y-4">
                      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)]">Actions</p>
                      <ul className="space-y-3">
                        {current.investigation_report.recommendations.map((rec, i) => (
                          <li key={i} className="text-[15px] leading-relaxed text-[var(--text)] pl-4 border-l-2 border-[var(--green)]">
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </>
              )}

              <button
                type="button"
                onClick={() => { setActiveId(null); setActive(null); }}
                className="w-full h-12 rounded-full border border-[var(--border)] bg-transparent text-[15px] font-medium text-[var(--text)] cursor-pointer hover:bg-[var(--surface)] transition-colors"
              >
                New analysis
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="py-6 text-center text-[12px] text-[var(--muted)]">
        IIT Hyderabad × Bank of India
      </footer>
    </div>
  );
}

function FindingsBlock({
  title,
  items,
}: {
  title: string;
  items?: { label: string; detail?: string }[];
}) {
  if (!items?.length) return null;
  return (
    <div className="rounded-3xl bg-[var(--surface)] overflow-hidden">
      <p className="px-6 pt-6 pb-2 text-[12px] uppercase tracking-widest text-[var(--muted)]">{title}</p>
      <ul>
        {items.map((item, i) => (
          <li key={i} className="px-6 py-4 border-t border-[var(--border)]">
            <p className="text-[15px] font-medium">{item.label}</p>
            {item.detail ? (
              <p className="text-[14px] text-[var(--muted)] mt-1 leading-relaxed line-clamp-3">{item.detail}</p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
