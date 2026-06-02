'use client';

import type React from 'react';
function inlineFormat(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('**')) {
      nodes.push(<strong key={key++} className="font-semibold">{tok.slice(2, -2)}</strong>);
    } else if (tok.startsWith('`')) {
      nodes.push(<code key={key++} className="font-mono px-1.5 py-0.5 rounded bg-zinc-950 text-[var(--blue)] text-[12.5px] border border-[var(--border)]">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith('*')) {
      nodes.push(<em key={key++}>{tok.slice(1, -1)}</em>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes.length ? nodes : [text];
}

function parseTableRow(line: string): string[] {
  return line.split('|').slice(1, -1).map((c) => c.trim());
}

function GeminiMark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <defs>
        <linearGradient id="gemini-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#4285f4" />
          <stop offset="50%" stopColor="#9b72cb" />
          <stop offset="100%" stopColor="#d96570" />
        </linearGradient>
      </defs>
      <path
        d="M12 2C12 8 8 12 2 12c6 0 10 4 10 10 0-6 4-10 10-10-6 0-10-4-10-10z"
        fill="url(#gemini-grad)"
      />
    </svg>
  );
}

export function MarkdownBody({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const blocks: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === '---') {
      blocks.push(<hr key={key++} className="my-3 border-[var(--border)]" />);
      i += 1;
      continue;
    }

    if (/^#{1,3}\s/.test(line)) {
      const level = line.match(/^#+/)![0].length;
      const content = line.replace(/^#+\s*/, '');
      const Tag = level === 1 ? 'h3' : level === 2 ? 'h4' : 'h5';
      blocks.push(
        <Tag key={key++} className={`font-semibold mt-3 mb-1 first:mt-0 ${level === 1 ? 'text-[16px]' : 'text-[15px]'}`}>
          {inlineFormat(content)}
        </Tag>,
      );
      i += 1;
      continue;
    }

    if (line.includes('|') && i + 1 < lines.length && /^\|?[\s\-:|]+\|/.test(lines[i + 1])) {
      const header = parseTableRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|')) {
        rows.push(parseTableRow(lines[i]));
        i += 1;
      }
      blocks.push(
        <div key={key++} className="overflow-x-auto my-2">
          <table className="w-full text-[13px] border-collapse">
            <thead>
              <tr>{header.map((h, hi) => <th key={hi} className="border border-[var(--border)] px-2 py-1.5 text-left font-medium bg-[var(--surface)]">{inlineFormat(h)}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, ri) => (
                <tr key={ri}>{row.map((cell, ci) => <td key={ci} className="border border-[var(--border)] px-2 py-1.5 align-top">{inlineFormat(cell)}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (/^[-*]\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s/.test(lines[i])) {
        items.push(lines[i].replace(/^[-*]\s+/, ''));
        i += 1;
      }
      blocks.push(
        <ul key={key++} className="list-disc pl-5 mb-2 space-y-1">
          {items.map((item, ii) => <li key={ii} className="text-[14px]">{inlineFormat(item)}</li>)}
        </ul>,
      );
      continue;
    }

    if (/^\d+\.\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s+/, ''));
        i += 1;
      }
      blocks.push(
        <ol key={key++} className="list-decimal pl-5 mb-2 space-y-1">
          {items.map((item, ii) => <li key={ii} className="text-[14px]">{inlineFormat(item)}</li>)}
        </ol>,
      );
      continue;
    }

    if (line.trim() === '') {
      i += 1;
      continue;
    }

    blocks.push(<p key={key++} className="mb-2 last:mb-0">{inlineFormat(line)}</p>);
    i += 1;
  }

  return <>{blocks}</>;
}

export function ChatBubble({ role, text }: { role: 'user' | 'ai'; text: string }) {
  if (role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[88%] rounded-2xl rounded-br-md bg-gradient-to-tr from-[var(--blue)]/20 to-[var(--blue)]/5 border border-[var(--blue)]/25 px-4 py-2.5 shadow-[0_2px_10px_rgba(59,130,246,0.04)]">
          <p className="text-[14px] text-[var(--text)] leading-relaxed">{text}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex gap-3 items-start">
      <div
        className="shrink-0 w-8 h-8 rounded-full flex items-center justify-center bg-[var(--surface-2)] border border-[var(--border)] shadow-sm"
        title="Gemini"
      >
        <GeminiMark size={18} />
      </div>
      <div className="min-w-0 flex-1 rounded-2xl rounded-tl-md bg-zinc-900/65 backdrop-blur-sm border border-[var(--border)] px-4 py-3 shadow-[0_4px_12px_rgba(0,0,0,0.15)]">
        <p className="text-[11px] font-bold text-[var(--blue)] mb-2 tracking-widest uppercase">Gemini Analyst</p>
        <div className="text-[14px] leading-relaxed text-zinc-200">
          <MarkdownBody text={text} />
        </div>
      </div>
    </div>
  );
}
