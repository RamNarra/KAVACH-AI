import type { RiskDecomposition } from '../lib/types';

interface RiskBreakdownCardProps {
  title: string;
  riskDecomposition?: RiskDecomposition;
  accent: string;
  excludeKey?: 'dynamic' | 'static';
}

export function RiskBreakdownCard({
  title,
  riskDecomposition,
  accent,
  excludeKey,
}: RiskBreakdownCardProps) {
  if (!riskDecomposition || !riskDecomposition.components) return null;

  const entries = Object.entries(riskDecomposition.components).filter(
    ([key]) => !excludeKey || key !== excludeKey
  );

  return (
    <div className="security-card p-6 space-y-4">
      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">
        {title}
      </p>
      <div className="space-y-3">
        {entries.map(([key, val]) => (
          <div key={key}>
            <div className="flex justify-between text-[13px] mb-1 capitalize">
              <span className="text-[var(--muted)]">{key.replace('_', ' ')}</span>
              <span className="tabular-nums font-semibold" style={{ color: accent }}>
                {String(val)}/100
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, Number(val) || 0)}%`, backgroundColor: accent }}
              />
            </div>
          </div>
        ))}
      </div>
      {riskDecomposition.summary && (
        <p className="text-[13px] text-[var(--muted)] leading-relaxed pt-2 border-t border-[var(--border)]/30">
          {riskDecomposition.summary}
        </p>
      )}
    </div>
  );
}
