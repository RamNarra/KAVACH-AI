import {
  Activity,
  Clock3,
  DatabaseZap,
  FileWarning,
  Info,
  Play,
  Radar,
} from 'lucide-react';
import {
  collectFindingEvidenceSnippets,
  derivePartialAnalysisNotices,
  getSeverityPresentation,
  type AnalysisResultForNotices,
  type PartialNoticeItem,
  type PartialNoticeKind,
  type RuntimeFindingSummary,
} from './dynamic-analysis-helpers';

export interface DynamicEvent {
  ts?: string;
  category?: string;
  action?: string;
  severity_hint?: 'low' | 'medium' | 'high' | 'critical';
  evidence?: string;
  args?: Record<string, unknown>;
  _dup_count?: number;
}

export interface TriggerTranscriptStep {
  step?: string;
  action?: string;
  result?: 'succeeded' | 'failed' | 'skipped';
  detail?: string;
  ts?: string;
}

export interface DynamicAnalysisEvidenceUi {
  status?: string;
  normalized_events?: DynamicEvent[];
  trigger_transcript?: TriggerTranscriptStep[];
  runtime_findings?: RuntimeFindingSummary[] | null;
  run_metadata?: {
    sandbox_status?: string;
    abi_compatible?: boolean;
    trigger_steps_attempted?: number;
    trigger_steps_succeeded?: number;
    event_count?: number;
    jadx_partial_output?: boolean;
    hook_packs?: string[];
    duration_seconds?: number;
    runtime_confidence?: string;
  } | null;
}

export type AnalysisResultForUi = AnalysisResultForNotices & {
  id?: string;
  evidence?: {
    dynamic_analysis?: DynamicAnalysisEvidenceUi;
  };
};

const cn = (...classes: Array<string | false | null | undefined>) =>
  classes.filter(Boolean).join(' ');

const NOTICE_VISUAL: Record<
  PartialNoticeKind,
  { panel: string; icon: string; label: string }
> = {
  no_dynamic: {
    panel: 'border-zinc-700/70 bg-zinc-950/60',
    icon: 'text-zinc-500',
    label: 'text-zinc-400',
  },
  unavailable: {
    panel: 'border-zinc-600/45 bg-zinc-900/45',
    icon: 'text-zinc-400',
    label: 'text-zinc-300',
  },
  partial_decompile: {
    panel: 'border-amber-500/25 bg-amber-950/15',
    icon: 'text-amber-400',
    label: 'text-amber-200',
  },
};

function NoticeIcon({ kind }: { kind: PartialNoticeKind }) {
  const iconClass = cn('w-5 h-5 shrink-0 mt-0.5', NOTICE_VISUAL[kind].icon);
  if (kind === 'partial_decompile') return <FileWarning className={iconClass} aria-hidden />;
  return <Info className={iconClass} aria-hidden />;
}

function formatTelemetryTimestamp(ts?: string) {
  if (!ts) return null;
  const parsed = Date.parse(ts);
  if (Number.isNaN(parsed)) return ts;
  return new Date(parsed).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function TriggerTimeline({ transcript }: { transcript: TriggerTranscriptStep[] }) {
  if (!transcript || transcript.length === 0) return null;

  return (
    <section className="space-y-3 opacity-90" aria-label="Trigger playbook timeline">
      <div className="flex items-center gap-2.5 pb-1 border-b border-indigo-500/15">
        <Clock3 className="w-4 h-4 text-indigo-400/90" />
        <h4 className="text-[11px] font-bold font-mono uppercase tracking-[0.2em] text-indigo-300/90">
          Trigger Playbook Timeline
        </h4>
        <span className="ml-auto text-[10px] font-mono text-zinc-600 uppercase tracking-widest">
          {transcript.length} steps
        </span>
      </div>
      <div className="relative border-l border-indigo-500/25 ml-2.5 space-y-2.5 pl-5 max-h-52 overflow-y-auto scrollbar-thin dynamic-reveal">
        {transcript.map((step, idx) => {
          const isSuccess = step.result === 'succeeded';
          const isFailed = step.result === 'failed';

          return (
            <article
              key={`${step.step ?? 'step'}-${idx}`}
              className="relative rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2.5"
            >
              <div
                className={cn(
                  'absolute -left-[23px] top-3 w-2.5 h-2.5 rounded-full border-2 border-zinc-950',
                  isSuccess ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.45)]' : isFailed ? 'bg-rose-500' : 'bg-zinc-600'
                )}
              />
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[11px] font-mono leading-relaxed">
                <span
                  className={cn(
                    'font-bold tracking-wider uppercase text-[10px]',
                    isSuccess ? 'text-emerald-400' : isFailed ? 'text-rose-400' : 'text-zinc-500'
                  )}
                >
                  {step.step ?? 'unknown_step'}
                </span>
                {step.ts ? (
                  <span className="text-[9px] text-zinc-600 tabular-nums">{formatTelemetryTimestamp(step.ts)}</span>
                ) : null}
              </div>
              <p className="mt-1 text-zinc-300 text-[11px] leading-snug">{step.action ?? 'No action detail available'}</p>
              {step.detail ? (
                <p className="mt-1.5 text-[10px] text-zinc-500 font-mono leading-relaxed break-words border-t border-zinc-800/80 pt-1.5">
                  {step.detail}
                </p>
              ) : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}

export function TelemetryStream({ events }: { events: DynamicEvent[] }) {
  if (!events || events.length === 0) return null;

  return (
    <section className="space-y-3 opacity-90" aria-label="Live telemetry intercepts">
      <div className="flex items-center justify-between gap-3 pb-1 border-b border-amber-500/15">
        <div className="flex items-center gap-2.5">
          <Radar className="w-4 h-4 text-amber-500/90" />
          <h4 className="text-[11px] font-bold font-mono uppercase tracking-[0.2em] text-amber-300/90">
            Live Telemetry Intercepts
          </h4>
        </div>
        <span className="text-[10px] font-bold bg-amber-500/8 px-2.5 py-0.5 rounded-md text-amber-300/90 border border-amber-500/20 tabular-nums">
          {events.length} signals
        </span>
      </div>
      <div className="max-h-64 overflow-y-auto scrollbar-thin space-y-2 flex flex-col dynamic-reveal">
        {events.map((ev, idx) => {
          const isHigh = ev.severity_hint === 'high';
          const isCritical = ev.severity_hint === 'critical';
          const severityClasses = isCritical
            ? 'text-rose-300 bg-rose-500/10 border-rose-500/25'
            : isHigh
              ? 'text-amber-300 bg-amber-500/10 border-amber-500/25'
              : 'text-indigo-300/90 bg-indigo-500/8 border-indigo-500/20';
          const detailParts = Object.entries(ev.args ?? {})
            .slice(0, 2)
            .map(([key, value]) => `${key}=${String(value)}`);
          const timeLabel = formatTelemetryTimestamp(ev.ts);

          return (
            <article
              key={`${ev.ts ?? 'event'}-${idx}`}
              className={cn(
                'rounded-lg border border-zinc-800/70 bg-zinc-950/50 font-mono text-[10px] p-3 space-y-2',
                isCritical && 'border-rose-500/25 bg-rose-950/20'
              )}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn('px-2 py-0.5 rounded-md border text-[9px] uppercase font-bold tracking-widest', severityClasses)}>
                  {ev.category ?? 'unknown'}
                </span>
                {timeLabel ? <span className="text-[9px] text-zinc-600 tabular-nums ml-auto">{timeLabel}</span> : null}
              </div>
              <p className="text-zinc-200 font-semibold text-[11px] leading-snug break-words">{ev.action ?? 'event'}</p>
              {ev.evidence ? (
                <p className="text-zinc-400/90 text-[10px] leading-relaxed whitespace-pre-wrap break-all border-l-2 border-zinc-700 pl-2.5 max-h-24 overflow-y-auto scrollbar-thin">
                  {ev.evidence}
                </p>
              ) : null}
              {detailParts.length > 0 ? (
                <p className="text-zinc-600 text-[9px] break-all leading-relaxed">{detailParts.join(' · ')}</p>
              ) : null}
              {ev._dup_count ? (
                <p className="text-zinc-600 text-[9px] italic">Suppressed duplicates: {ev._dup_count}</p>
              ) : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}

export function LiveOpsStrip({
  activeResult,
  elapsedSeconds,
}: {
  activeResult: AnalysisResultForUi;
  elapsedSeconds: number;
}) {
  const meta = activeResult.evidence?.dynamic_analysis?.run_metadata;
  const isProcessing = activeResult.status === 'PROCESSING';
  const hasRunMetadata = Boolean(meta && Object.keys(meta).length > 0);
  const sandboxStatusLabel = isProcessing
    ? 'RUNNING'
    : meta?.sandbox_status || (activeResult.status === 'COMPLETED' ? 'UNAVAILABLE' : 'WAITING');
  const isUnavailableTelemetry =
    !isProcessing && activeResult.status === 'COMPLETED' && sandboxStatusLabel === 'UNAVAILABLE';
  const isHealthySandbox = meta?.sandbox_status === 'COMPLETED';
  const durationLabel = meta?.duration_seconds
    ? `${meta.duration_seconds}s`
    : isProcessing
      ? `${elapsedSeconds}s`
      : 'N/A';
  const confidenceLabel = meta?.runtime_confidence || (isProcessing ? 'CALCULATING' : hasRunMetadata ? 'NONE' : 'UNAVAILABLE');

  return (
    <div className="sticky top-[73px] z-40 mb-6 w-full max-w-5xl mx-auto px-4 select-none">
      <div
        className={cn(
          'rounded-xl backdrop-blur-xl p-3.5 shadow-lg flex flex-wrap gap-x-5 gap-y-3 sm:gap-6 items-center justify-between text-[11px] font-mono overflow-x-auto',
          isUnavailableTelemetry
            ? 'border border-zinc-600/50 bg-zinc-950/85 text-zinc-400'
            : 'border border-indigo-500/20 bg-black/80 text-zinc-300'
        )}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={cn(
              'w-2.5 h-2.5 rounded-full shrink-0',
              isProcessing && 'bg-amber-500 motion-safe-pulse',
              !isProcessing && isHealthySandbox && 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.35)]',
              isUnavailableTelemetry && 'bg-zinc-400 ring-2 ring-zinc-500/35',
              !isProcessing && !isHealthySandbox && !isUnavailableTelemetry && 'bg-zinc-500'
            )}
          />
          <div className="flex flex-col min-w-0">
            <span
              className={cn(
                'uppercase tracking-[0.18em] font-bold leading-tight',
                isUnavailableTelemetry ? 'text-zinc-300' : 'text-indigo-300'
              )}
            >
              Sandbox: {sandboxStatusLabel}
            </span>
            {isUnavailableTelemetry ? (
              <span className="text-[9px] text-zinc-500 uppercase tracking-widest mt-0.5">
                Historical scan — telemetry not persisted
              </span>
            ) : null}
          </div>
        </div>

        <div className="flex items-center gap-2 text-zinc-500 uppercase shrink-0">
          <Play className="w-3.5 h-3.5 text-indigo-400/80" />
          <span>
            Triggers{' '}
            <span className="text-zinc-300 tabular-nums">
              {meta?.trigger_steps_succeeded || 0}/{meta?.trigger_steps_attempted || 0}
            </span>
          </span>
        </div>

        <div className="flex items-center gap-2 text-zinc-500 uppercase shrink-0">
          <DatabaseZap className="w-3.5 h-3.5 text-amber-500/80" />
          <span>
            Events <span className="text-zinc-300 tabular-nums">{meta?.event_count || 0}</span>
          </span>
        </div>

        <div className="flex items-center gap-2 text-zinc-500 uppercase shrink-0">
          <Clock3 className="w-3.5 h-3.5 text-zinc-500" />
          <span className="text-zinc-300 tabular-nums">{durationLabel}</span>
        </div>

        <div
          className={cn(
            'uppercase font-bold shrink-0 px-2 py-0.5 rounded-md border',
            meta?.runtime_confidence === 'full'
              ? 'text-emerald-400 border-emerald-500/25 bg-emerald-500/5'
              : isUnavailableTelemetry
                ? 'text-zinc-400 border-zinc-600/40 bg-zinc-800/30'
                : 'text-amber-400/90 border-amber-500/20 bg-amber-500/5'
          )}
        >
          Confidence: {confidenceLabel}
        </div>

        {meta?.jadx_partial_output ? (
          <div className="uppercase font-bold text-amber-300 border border-amber-500/25 bg-amber-500/10 rounded-md px-2.5 py-1 shrink-0 text-[10px] tracking-wider">
            JADX Partial
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function PartialAnalysisNotice({ activeResult }: { activeResult: AnalysisResultForUi }) {
  const notices = derivePartialAnalysisNotices(activeResult);
  if (notices.length === 0) return null;

  return (
    <div className="space-y-3 dynamic-reveal" data-testid="partial-analysis-notice">
      {notices.map((notice) => (
        <NoticeCard key={`${notice.kind}-${notice.title}`} notice={notice} />
      ))}
    </div>
  );
}

function NoticeCard({ notice }: { notice: PartialNoticeItem }) {
  const visual = NOTICE_VISUAL[notice.kind];

  return (
    <div className={cn('rounded-xl border p-4 sm:p-5 flex gap-3.5 sm:gap-4', visual.panel)}>
      <NoticeIcon kind={notice.kind} />
      <div className="min-w-0 space-y-1.5">
        <h4 className={cn('text-xs font-bold uppercase tracking-[0.16em] font-mono', visual.label)}>
          {notice.title}
        </h4>
        <p className="text-sm leading-relaxed text-zinc-400/95">{notice.body}</p>
      </div>
    </div>
  );
}

export function RuntimeFindingsPanel({ findings }: { findings: RuntimeFindingSummary[] | null | undefined }) {
  const safeFindings = findings ?? [];

  if (safeFindings.length === 0) {
    return (
      <div
        className="rounded-xl border border-dashed border-zinc-700/50 bg-zinc-950/25 px-5 py-6 text-center sm:text-left"
        data-testid="runtime-findings-empty"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 text-zinc-500 mb-2 justify-center sm:justify-start">
          <Info className="w-4 h-4 shrink-0 opacity-70" />
          <h4 className="text-[11px] font-bold font-mono uppercase tracking-[0.2em]">Runtime Findings</h4>
        </div>
        <p className="text-sm text-zinc-500/90 font-mono leading-relaxed max-w-prose">
          No clustered runtime findings were recorded for this document.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="runtime-findings-populated">
      <div className="flex items-end justify-between gap-3 border-b border-indigo-500/15 pb-2">
        <div className="flex items-center gap-2.5">
          <Activity className="w-4 h-4 text-indigo-400" />
          <h4 className="text-[11px] font-bold font-mono uppercase tracking-[0.2em] text-indigo-300">
            Runtime Findings
          </h4>
        </div>
        <span className="text-[10px] font-bold bg-indigo-500/10 px-2.5 py-1 rounded-md text-indigo-200/90 border border-indigo-500/25 tabular-nums">
          {safeFindings.length} clustered
        </span>
      </div>
      <div className="grid gap-4 md:grid-cols-2 dynamic-reveal">
        {safeFindings.map((finding, idx) => {
          const severity = getSeverityPresentation(finding.severity);
          const snippets = collectFindingEvidenceSnippets(finding);
          const label = finding.title ?? finding.category ?? 'Runtime finding';

          return (
            <article
              key={finding.id ?? `runtime-finding-${idx}`}
              className="group rounded-xl border border-zinc-800/90 bg-gradient-to-b from-zinc-900/50 to-black/40 p-5 space-y-3.5 shadow-sm transition-colors hover:border-indigo-500/25"
            >
              <div className="flex items-start justify-between gap-3">
                <span
                  className={cn(
                    'text-[10px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-md border shrink-0',
                    severity.classes
                  )}
                >
                  {severity.label}
                </span>
                <div className="flex flex-wrap justify-end gap-1.5 text-[9px] font-mono uppercase tracking-wider text-zinc-500">
                  <span className="px-1.5 py-0.5 rounded bg-zinc-900/80 border border-zinc-800">
                    {finding.source ?? 'dynamic'}
                  </span>
                  {typeof finding.confidence === 'number' ? (
                    <span className="px-1.5 py-0.5 rounded bg-zinc-900/80 border border-zinc-800 tabular-nums">
                      {(finding.confidence * 100).toFixed(0)}% conf
                    </span>
                  ) : null}
                  <span className="px-1.5 py-0.5 rounded bg-zinc-900/80 border border-zinc-800 tabular-nums">
                    {finding.event_count ?? 0} evt
                  </span>
                </div>
              </div>
              <div className="space-y-2">
                <h5 className="text-lg font-bold text-zinc-50 tracking-tight leading-snug">{label}</h5>
                <p className="text-sm text-zinc-400/95 leading-relaxed">
                  {finding.summary ?? 'No summary available for this runtime cluster.'}
                </p>
              </div>
              {snippets.length > 0 ? (
                <div className="space-y-2 pt-3 border-t border-zinc-800/80">
                  <p className="text-[9px] font-mono uppercase tracking-[0.18em] text-zinc-500">Evidence</p>
                  <ul className="space-y-1.5">
                    {snippets.map((snippet, snippetIdx) => (
                      <li
                        key={`${finding.id ?? idx}-snippet-${snippetIdx}`}
                        className="text-[11px] font-mono text-zinc-300/90 bg-black/50 border border-zinc-800/90 border-l-2 border-l-indigo-500/40 rounded-r-md rounded-l-sm px-2.5 py-2 break-all leading-relaxed"
                      >
                        {snippet}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
    </div>
  );
}

/** Minimal operator-facing slice used for smoke tests and page composition. */
export function DynamicAnalysisOperatorSmokeView({
  activeResult,
  elapsedSeconds = 0,
}: {
  activeResult: AnalysisResultForUi;
  elapsedSeconds?: number;
}) {
  const dynamic = activeResult.evidence?.dynamic_analysis;
  const telemetryEvents = dynamic?.normalized_events ?? [];
  const triggerTranscript = dynamic?.trigger_transcript ?? [];
  const partialNotices = derivePartialAnalysisNotices(activeResult);
  const showDynamicSection = Boolean(dynamic);

  return (
    <div data-testid="dynamic-analysis-operator-view" className="space-y-6">
      <LiveOpsStrip activeResult={activeResult} elapsedSeconds={elapsedSeconds} />
      {partialNotices.length > 0 ? <PartialAnalysisNotice activeResult={activeResult} /> : null}
      {showDynamicSection ? (
        <div data-testid="dynamic-evidence-section" className="space-y-8 pt-1">
          <RuntimeFindingsPanel findings={dynamic?.runtime_findings ?? undefined} />
          {telemetryEvents.length > 0 ? <TelemetryStream events={telemetryEvents} /> : null}
          {triggerTranscript.length > 0 ? <TriggerTimeline transcript={triggerTranscript} /> : null}
        </div>
      ) : null}
    </div>
  );
}
