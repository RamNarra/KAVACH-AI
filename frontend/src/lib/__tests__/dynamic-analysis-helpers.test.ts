import { describe, expect, it } from 'vitest';
import {
  olderCompletedShellDoc,
  recentCompletedFullDoc,
} from '../dynamic-analysis-fixtures';
import {
  collectFindingEvidenceSnippets,
  derivePartialAnalysisNotices,
  getSeverityPresentation,
  type AnalysisResultForNotices,
  type RuntimeFindingSummary,
} from '../dynamic-analysis-helpers';

const recentCompletedFull = { status: recentCompletedFullDoc.status, evidence: recentCompletedFullDoc.evidence };
const olderCompletedShell = { status: olderCompletedShellDoc.status, evidence: olderCompletedShellDoc.evidence };

const completedNoDynamic: AnalysisResultForNotices = {
  status: 'COMPLETED',
  evidence: {},
};

function noticeKinds(result: AnalysisResultForNotices) {
  return derivePartialAnalysisNotices(result).map((n) => n.kind);
}

describe('derivePartialAnalysisNotices', () => {
  it('returns no notices for recent completed doc with full dynamic_analysis', () => {
    expect(derivePartialAnalysisNotices(recentCompletedFull)).toEqual([]);
  });

  it('returns unavailable notice for older shell doc with null subfields', () => {
    const notices = derivePartialAnalysisNotices(olderCompletedShell);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.kind).toBe('unavailable');
    expect(notices[0]?.title).toBe('Dynamic Evidence Unavailable');
    expect(notices[0]?.body).toMatch(/not a scan failure/i);
    expect(notices[0]?.tone).toBe('neutral');
  });

  it('returns no_dynamic when dynamic_analysis object is missing', () => {
    const notices = derivePartialAnalysisNotices(completedNoDynamic);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.kind).toBe('no_dynamic');
    expect(notices[0]?.title).toBe('No Dynamic Analysis Payload');
  });

  it('returns partial decompilation notice only when jadx_partial_output is true', () => {
    const withPartial: AnalysisResultForNotices = {
      status: 'COMPLETED',
      evidence: {
        dynamic_analysis: {
          status: 'COMPLETED',
          normalized_events: [{}],
          run_metadata: { jadx_partial_output: true },
        },
      },
    };
    const kinds = noticeKinds(withPartial);
    expect(kinds).toContain('partial_decompile');
    expect(kinds).not.toContain('no_dynamic');
  });

  it('does not emit partial decompilation for false, null, or missing jadx_partial_output', () => {
    const falseFlag: AnalysisResultForNotices = {
      status: 'COMPLETED',
      evidence: {
        dynamic_analysis: {
          status: 'COMPLETED',
          normalized_events: [{}],
          run_metadata: { jadx_partial_output: false },
        },
      },
    };
    const nullFlag: AnalysisResultForNotices = {
      status: 'COMPLETED',
      evidence: {
        dynamic_analysis: {
          status: 'COMPLETED',
          normalized_events: [{}],
          run_metadata: { jadx_partial_output: null as unknown as undefined },
        },
      },
    };
    const missingFlag: AnalysisResultForNotices = {
      status: 'COMPLETED',
      evidence: {
        dynamic_analysis: {
          status: 'COMPLETED',
          normalized_events: [{}],
          run_metadata: {},
        },
      },
    };

    expect(noticeKinds(falseFlag)).not.toContain('partial_decompile');
    expect(noticeKinds(nullFlag)).not.toContain('partial_decompile');
    expect(noticeKinds(missingFlag)).not.toContain('partial_decompile');
  });

  it('uses incomplete/unavailable wording for non-COMPLETED sandbox status with data present', () => {
    const running: AnalysisResultForNotices = {
      status: 'COMPLETED',
      evidence: {
        dynamic_analysis: {
          status: 'RUNNING',
          normalized_events: [{ category: 'crypto' }],
          run_metadata: { sandbox_status: 'RUNNING' },
        },
      },
    };
    const notices = derivePartialAnalysisNotices(running);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.kind).toBe('unavailable');
    expect(notices[0]?.title).toBe('Dynamic Analysis Incomplete');
    expect(notices[0]?.body).toContain('RUNNING');
    expect(notices[0]?.body).not.toMatch(/scan failed|analysis failed/i);
    expect(notices[0]?.tone).toBe('caution');
  });
});

describe('collectFindingEvidenceSnippets', () => {
  it('prefers evidence_items when present and limits to 3', () => {
    const finding: RuntimeFindingSummary = {
      evidence_items: ['a', 'b', 'c', 'd'],
      sample_events: [{ evidence: 'should-not-use' }],
    };
    expect(collectFindingEvidenceSnippets(finding)).toEqual(['a', 'b', 'c']);
  });

  it('falls back to sample_events when evidence_items missing', () => {
    const finding: RuntimeFindingSummary = {
      sample_events: [
        { evidence: 'ev1' },
        { action: 'act2' },
        { category: 'cat3' },
        { action: 'act4' },
      ],
    };
    expect(collectFindingEvidenceSnippets(finding)).toEqual(['ev1', 'act2']);
  });

  it('handles null and empty arrays safely', () => {
    expect(collectFindingEvidenceSnippets({})).toEqual([]);
    expect(
      collectFindingEvidenceSnippets({
        evidence_items: null as unknown as undefined,
        sample_events: null as unknown as undefined,
      })
    ).toEqual([]);
    expect(
      collectFindingEvidenceSnippets({
        evidence_items: [],
        sample_events: [],
      })
    ).toEqual([]);
  });
});

describe('getSeverityPresentation', () => {
  it('maps known severities to distinct style classes', () => {
    expect(getSeverityPresentation('CRITICAL').classes).toContain('rose');
    expect(getSeverityPresentation('HIGH').classes).toContain('rose');
    expect(getSeverityPresentation('MEDIUM').classes).toContain('amber');
    expect(getSeverityPresentation('LOW').classes).toContain('emerald');
    expect(getSeverityPresentation('INFO').classes).toContain('indigo');
  });

  it('normalizes lowercase severity hints from live data', () => {
    const medium = getSeverityPresentation('medium');
    expect(medium.label).toBe('MEDIUM');
    expect(medium.classes).toContain('amber');
  });

  it('uses neutral zinc styling for unknown severity while preserving label text', () => {
    const unknown = getSeverityPresentation('unexpected');
    expect(unknown.label).toBe('UNEXPECTED');
    expect(unknown.classes).toContain('zinc');
    expect(unknown.classes).not.toContain('amber');
  });

  it('defaults missing severity to INFO', () => {
    const info = getSeverityPresentation();
    expect(info.label).toBe('INFO');
    expect(info.classes).toContain('indigo');
  });
});
