/**
 * Pure helpers for dynamic-analysis UI state.
 * Extracted for regression tests against live Firestore document shapes.
 */

export type PartialNoticeKind = 'no_dynamic' | 'unavailable' | 'partial_decompile';

export interface PartialNoticeItem {
  kind: PartialNoticeKind;
  title: string;
  body: string;
  tone: 'neutral' | 'caution' | 'info';
}

export interface RuntimeFindingSummary {
  id?: string;
  title?: string;
  severity?: string;
  category?: string;
  summary?: string;
  source?: string;
  confidence?: number;
  event_count?: number;
  evidence_items?: string[];
  sample_events?: Array<{ action?: string; evidence?: string; category?: string }>;
  static_finding_refs?: string[];
}

export interface DynamicAnalysisEvidence {
  status?: string;
  normalized_events?: unknown[];
  trigger_transcript?: unknown[];
  runtime_findings?: RuntimeFindingSummary[];
  run_metadata?: {
    sandbox_status?: string;
    jadx_partial_output?: boolean;
    event_count?: number;
    runtime_confidence?: string;
    trigger_steps_attempted?: number;
    trigger_steps_succeeded?: number;
    duration_seconds?: number;
  };
}

export interface AnalysisResultForNotices {
  status: 'PROCESSING' | 'COMPLETED' | 'FAILED';
  evidence?: {
    dynamic_analysis?: DynamicAnalysisEvidence;
  };
}

export function getSeverityPresentation(severity?: string) {
  const label = (severity ?? 'INFO').toUpperCase();
  switch (label) {
    case 'CRITICAL':
      return { label, classes: 'text-rose-300 bg-rose-500/15 border-rose-500/30' };
    case 'HIGH':
      return { label, classes: 'text-rose-400 bg-rose-500/10 border-rose-500/20' };
    case 'MEDIUM':
      return { label, classes: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
    case 'LOW':
      return { label, classes: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' };
    case 'INFO':
      return { label, classes: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20' };
    default:
      return { label, classes: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20' };
  }
}

export function collectFindingEvidenceSnippets(finding: RuntimeFindingSummary): string[] {
  const fromItems = (finding.evidence_items ?? []).filter(Boolean);
  if (fromItems.length > 0) return fromItems.slice(0, 3);

  return (finding.sample_events ?? [])
    .map((event) => event.evidence || event.action || event.category)
    .filter((value): value is string => Boolean(value))
    .slice(0, 2);
}

export function derivePartialAnalysisNotices(activeResult: AnalysisResultForNotices): PartialNoticeItem[] {
  const dynamic = activeResult.evidence?.dynamic_analysis;
  const notices: PartialNoticeItem[] = [];

  if (!dynamic) {
    notices.push({
      kind: 'no_dynamic',
      title: 'No Dynamic Analysis Payload',
      body: 'This completed scan has no runtime sandbox evidence attached. Static synthesis remains authoritative; no runtime correlation was recorded for this document.',
      tone: 'neutral',
    });
    return notices;
  }

  const meta = dynamic.run_metadata;
  const hasRunMetadata = Boolean(meta && Object.keys(meta).length > 0);
  const hasEvents = (dynamic.normalized_events?.length ?? 0) > 0;
  const hasTranscript = (dynamic.trigger_transcript?.length ?? 0) > 0;
  const hasFindings = (dynamic.runtime_findings?.length ?? 0) > 0;
  const status = (dynamic.status ?? '').toUpperCase();
  const isHistoricalShell = !hasRunMetadata && !hasEvents && !hasTranscript && !hasFindings;

  if (isHistoricalShell) {
    notices.push({
      kind: 'unavailable',
      title: 'Dynamic Evidence Unavailable',
      body: 'A dynamic_analysis record exists, but runtime metadata, events, transcript, and findings are empty or null. This is common on older completed scans and is not a scan failure.',
      tone: 'neutral',
    });
  } else if (status && status !== 'COMPLETED') {
    notices.push({
      kind: 'unavailable',
      title: 'Dynamic Analysis Incomplete',
      body: `Runtime sandbox reported status "${status}". Use static findings as primary evidence until dynamic telemetry is complete.`,
      tone: 'caution',
    });
  }

  if (meta?.jadx_partial_output === true) {
    notices.push({
      kind: 'partial_decompile',
      title: 'Partial Decompilation',
      body: 'JADX produced partial output for this scan. Static-to-runtime correlation may be incomplete; prioritize directly observed runtime signals.',
      tone: 'caution',
    });
  }

  return notices;
}
