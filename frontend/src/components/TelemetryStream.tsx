import { DynamicAnalysisOperatorSmokeView, type AnalysisResultForUi } from '../lib/dynamic-analysis-ui';
import type { AnalysisDoc } from '../lib/types';

interface TelemetryStreamProps {
  title: string;
  current: AnalysisDoc;
}

function toDynamicUi(doc: AnalysisDoc): AnalysisResultForUi {
  return {
    id: doc.id,
    status: doc.status,
    evidence: doc.evidence as AnalysisResultForUi['evidence'],
  };
}

export function TelemetryStream({ title, current }: TelemetryStreamProps) {
  return (
    <div className="security-card p-6 border border-[var(--border)]">
      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] mb-4 font-semibold tracking-wider">{title}</p>
      <DynamicAnalysisOperatorSmokeView activeResult={toDynamicUi(current)} />
    </div>
  );
}
