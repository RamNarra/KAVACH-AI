'use client';

import { useEffect, useRef } from 'react';

interface TerminalLogsProps {
  logs: string[];
}

export default function TerminalLogs({ logs }: TerminalLogsProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="rounded-3xl border border-[var(--border)] bg-[#040409]/90 p-5 shadow-2xl backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-4 select-none">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-red-500/80 animate-pulse" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <span className="w-3 h-3 rounded-full bg-green-500/80" />
          <span className="text-[12.5px] font-bold font-mono tracking-widest text-[var(--muted)] ml-2 uppercase">
            LIVE TELEMETRY LAB LOGS
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-[10px] font-mono text-[var(--blue)] font-bold tracking-wider bg-[var(--blue)]/10 px-2 py-0.5 rounded-full">
          <span>PORT: 8080</span>
        </div>
      </div>
      <div
        ref={containerRef}
        className="h-[180px] overflow-y-auto font-mono text-[12.5px] space-y-1.5 pr-2 no-scrollbar scroll-smooth"
        style={{ scrollbarWidth: 'none' }}
      >
        {logs.length === 0 ? (
          <div className="text-zinc-600 italic">No telemetry streams yet. Start APK analysis to activate...</div>
        ) : (
          logs.map((log, index) => {
            let color = 'text-zinc-400';
            if (log.includes('[ERROR]') || log.includes('FAILED')) {
              color = 'text-red-400 font-bold';
            } else if (log.includes('[WARN]')) {
              color = 'text-yellow-400';
            } else if (log.includes('[FRIDA]')) {
              color = 'text-indigo-400 font-semibold';
            } else if (log.includes('COMPLETED') || log.includes('succeeded')) {
              color = 'text-emerald-400';
            }

            return (
              <div key={index} className={`leading-relaxed break-all select-text ${color}`}>
                <span className="text-zinc-600 mr-2 border-r border-zinc-800 pr-1.5">
                  {(index + 1).toString().padStart(3, '0')}
                </span>
                {log}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
