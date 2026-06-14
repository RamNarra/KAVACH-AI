import { useState } from 'react';
import type { FraudBadge, ThreatLevel } from '../lib/types';

interface ScoreCardProps {
  score: number;
  level: ThreatLevel;
  accent: string;
  absoluteScore?: number;
  fraudScore?: number;
  filename: string;
  activeBadges: FraudBadge[];
  logs: string[];
  chatOpen: boolean;
  setChatOpen: (open: boolean) => void;
  downloadReport: () => void;
  isDemo: boolean;
  reset: () => void;
  isAnalyzing?: boolean;
}

export function ScoreCard({
  score,
  level,
  accent,
  absoluteScore,
  fraudScore,
  filename,
  activeBadges,
  logs,
  chatOpen,
  setChatOpen,
  downloadReport,
  isDemo,
  reset,
  isAnalyzing = false,
}: ScoreCardProps) {
  const [rubricTab, setRubricTab] = useState<'confidence' | 'severity'>('confidence');

  return (
    <div className={`space-y-6 lg:sticky lg:top-6 lg:max-h-[calc(100vh-3rem)] lg:overflow-y-auto pr-1.5 scrollbar-thin transition-all duration-500 ${chatOpen ? 'lg:col-span-3' : 'lg:col-span-4'}`}>
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
        <p className="text-[14px] font-medium break-all text-[var(--text)]">{filename}</p>
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

      {/* Security Classification Glossary & Severity Rubric Guide */}
      <div className="security-card p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-[var(--border)] pb-2">
          <span className="text-[11px] uppercase tracking-widest text-[var(--muted)] font-bold">Analysis Methodology</span>
          <div className="flex gap-1.5">
            <button
              onClick={() => setRubricTab('confidence')}
              className={`text-[9px] font-bold px-2 py-0.5 rounded-full transition-all ${
                rubricTab === 'confidence'
                  ? 'bg-[var(--blue)]/20 text-[var(--blue)] border border-[var(--blue)]/30'
                  : 'bg-transparent text-[var(--muted)] hover:text-[var(--text)]'
              }`}
            >
              Confidence
            </button>
            <button
              onClick={() => setRubricTab('severity')}
              className={`text-[9px] font-bold px-2 py-0.5 rounded-full transition-all ${
                rubricTab === 'severity'
                  ? 'bg-[var(--blue)]/20 text-[var(--blue)] border border-[var(--blue)]/30'
                  : 'bg-transparent text-[var(--muted)] hover:text-[var(--text)]'
              }`}
            >
              Severity
            </button>
          </div>
        </div>

        <div className="space-y-3 min-h-[140px] text-[12px] leading-relaxed">
          {rubricTab === 'confidence' ? (
            <div className="space-y-3.5">
              <div className="space-y-1">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/25">
                    ✓ Evidence-Backed
                  </span>
                </div>
                <p className="text-[11.5px] text-[var(--muted)]">
                  Verified statically or dynamically using decompilation (APKTool, JADX) and runtime monitors. Refers to tangible artifacts like hardcoded endpoint strings, exposed components, or unencrypted cleartext configs.
                </p>
              </div>
              <div className="space-y-1 pt-1.5 border-t border-[var(--border)]/40">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#eab308]/15 text-[#eab308] border border-[#eab308]/25">
                    ⚠ AI Inferred
                  </span>
                </div>
                <p className="text-[11.5px] text-[var(--muted)]">
                  Deduced via Gemini's semantic model analyzing heuristic threat shapes, intent routing context, or matching patterns resembling known banking malware behavior (e.g. potential overlay templates, logic bypass).
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="grid grid-cols-[65px_1fr] gap-2 items-start">
                <span className="text-[9.5px] font-extrabold text-center px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-800/40 uppercase">Critical</span>
                <span className="text-[11.5px] text-[var(--muted)]">Active trojan indicators, SMS interception, or data exfiltration hooks. Imminent risk.</span>
              </div>
              <div className="grid grid-cols-[65px_1fr] gap-2 items-start pt-1.5 border-t border-[var(--border)]/30">
                <span className="text-[9.5px] font-extrabold text-center px-1.5 py-0.5 rounded bg-orange-950/40 text-orange-400 border border-orange-800/40 uppercase">High</span>
                <span className="text-[11.5px] text-[var(--muted)]">Cleartext transport config, exported activities with zero safety bounds, or critical key leakage.</span>
              </div>
              <div className="grid grid-cols-[65px_1fr] gap-2 items-start pt-1.5 border-t border-[var(--border)]/30">
                <span className="text-[9.5px] font-extrabold text-center px-1.5 py-0.5 rounded bg-yellow-950/40 text-yellow-400 border border-yellow-800/40 uppercase">Medium</span>
                <span className="text-[11.5px] text-[var(--muted)]">Weak cryptography parameters, insecure storage access paths, or local IP exposure.</span>
              </div>
              <div className="grid grid-cols-[65px_1fr] gap-2 items-start pt-1.5 border-t border-[var(--border)]/30">
                <span className="text-[9.5px] font-extrabold text-center px-1.5 py-0.5 rounded bg-zinc-900/60 text-zinc-400 border border-zinc-800/40 uppercase">Low</span>
                <span className="text-[11.5px] text-[var(--muted)]">Unused manifest permissions, verbose debugging logs enabled, or minor metadata anomalies.</span>
              </div>
            </div>
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
            onClick={downloadReport}
            disabled={isAnalyzing}
            className={`flex-1 h-12 rounded-full border text-[13px] font-semibold cursor-pointer transition-all flex items-center justify-center gap-1.5 ${
              isAnalyzing 
                ? 'bg-transparent border-zinc-800 text-zinc-600 cursor-not-allowed opacity-50'
                : 'bg-transparent border-[var(--border)] text-[var(--text)] hover:bg-[var(--surface-2)]'
            }`}
            title={isAnalyzing ? "Analysis in progress..." : "Export executive PDF report"}
          >
            📥 Export PDF
          </button>
        )}
      </div>

      <button type="button" onClick={reset} className="w-full h-12 rounded-full border border-[var(--border)] bg-transparent text-[14px] font-semibold cursor-pointer hover:bg-[var(--surface-2)] transition-all">
        New Analysis
      </button>
    </div>
  );
}
