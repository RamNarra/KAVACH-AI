interface Technique {
  id: string;
  name: string;
  sources?: Array<{ source?: string; detail?: string }>;
  tactic?: string;
}

interface AttackMappingProps {
  activeAttackTechniques: Technique[];
  expandedTechniques: Record<string, boolean>;
  setExpandedTechniques: (updater: (prev: Record<string, boolean>) => Record<string, boolean>) => void;
  mitreExpanded: boolean;
  setMitreExpanded: (expanded: boolean) => void;
}

export function AttackMapping({
  activeAttackTechniques,
  expandedTechniques,
  setExpandedTechniques,
  mitreExpanded,
  setMitreExpanded,
}: AttackMappingProps) {
  if (activeAttackTechniques.length === 0) return null;

  const items = activeAttackTechniques;
  const showLimit = 6;
  const hasMore = items.length > showLimit;
  const visibleItems = (hasMore && !mitreExpanded) ? items.slice(0, showLimit) : items;
  const remainingCount = items.length - showLimit;

  return (
    <div className="space-y-3">
      <p className="text-[12px] uppercase tracking-widest text-[var(--muted)] font-semibold tracking-wider">MITRE ATT&CK Matrix</p>
      <div className="space-y-2">
        {visibleItems.map((t) => {
          const isExpanded = !!expandedTechniques[t.id];
          return (
            <div
              key={t.id}
              onClick={() => setExpandedTechniques(prev => ({ ...prev, [t.id]: !prev[t.id] }))}
              className="rounded-2xl bg-[var(--surface)] border border-[var(--border)] p-4 space-y-1.5 hover:border-[var(--blue)]/40 hover:bg-[var(--surface-2)]/20 cursor-pointer select-none transition-all duration-300"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--blue)]/15 text-[var(--blue)] border border-[var(--blue)]/20 font-semibold">{t.id}</span>
                  <span className="text-[14px] font-semibold">{t.name}</span>
                  {t.sources && t.sources.length > 0 && (
                    <span className="text-[11.5px] text-[var(--muted)]">({t.sources.length} detection{t.sources.length > 1 ? 's' : ''})</span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {t.tactic && (
                    <span className="text-[11px] px-2 py-0.5 rounded-full bg-[var(--surface-2)] text-[var(--muted)] whitespace-nowrap border border-[var(--border)]">{t.tactic}</span>
                  )}
                  <span className={`text-[10px] text-[var(--muted)] transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>▼</span>
                </div>
              </div>
              {isExpanded && t.sources && t.sources.length > 0 && (
                <ul className="space-y-1.5 pt-2.5 border-t border-[var(--border)] mt-2">
                  {t.sources.map((s, si) => (
                    <li key={si} className="text-[13px] text-[var(--muted)] pl-3 border-l-2 border-[var(--blue)]/30">
                      <span className="text-[var(--text)] font-medium">{String(s.source || '')}</span>{s.detail ? ` — ${String(s.detail)}` : ''}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
        {hasMore && (
          <button
            type="button"
            onClick={() => setMitreExpanded(!mitreExpanded)}
            className="w-full py-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)]/40 backdrop-blur-md text-[13px] text-[var(--blue)] font-semibold cursor-pointer hover:bg-[var(--blue)]/10 hover:border-[var(--blue)]/30 transition-all duration-200 flex items-center justify-center gap-2"
          >
            {mitreExpanded ? 'Show less ↑' : `Read (${remainingCount} more) ↓`}
          </button>
        )}
      </div>
    </div>
  );
}
