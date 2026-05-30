import type { AnalysisResultForUi } from './dynamic-analysis-ui';

/** Recent completed scan with full dynamic_analysis telemetry (live-shape fixture). */
export const recentCompletedFullDoc: AnalysisResultForUi = {
  id: 'fixture-recent-completed',
  status: 'COMPLETED',
  evidence: {
    dynamic_analysis: {
      status: 'COMPLETED',
      normalized_events: [
        {
          category: 'network',
          action: 'http.request',
          severity_hint: 'medium',
          evidence: 'GET http://example.com/api',
        },
      ],
      trigger_transcript: [
        { step: 'launch', action: 'Start main activity', result: 'succeeded' },
      ],
      runtime_findings: [
        {
          id: 'rf_cleartext_http',
          title: 'Cleartext HTTP observed',
          severity: 'MEDIUM',
          summary: 'Application issued plaintext HTTP during sandbox execution.',
          evidence_items: ['GET http://example.com/api'],
          event_count: 3,
          source: 'dynamic',
        },
      ],
      run_metadata: {
        sandbox_status: 'COMPLETED',
        event_count: 12,
        runtime_confidence: 'full',
        jadx_partial_output: false,
        trigger_steps_attempted: 3,
        trigger_steps_succeeded: 3,
        duration_seconds: 42,
      },
    },
  },
};

/** Older completed scan with dynamic_analysis shell and null subfields. */
export const olderCompletedShellDoc: AnalysisResultForUi = {
  id: 'fixture-older-shell',
  status: 'COMPLETED',
  evidence: {
    dynamic_analysis: {
      status: 'COMPLETED',
      normalized_events: null as unknown as undefined,
      trigger_transcript: null as unknown as undefined,
      runtime_findings: null as unknown as undefined,
      run_metadata: null as unknown as undefined,
    },
  },
};
