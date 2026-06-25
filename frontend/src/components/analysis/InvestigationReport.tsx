'use client';
import { useState, memo } from 'react';
import { Box, Typography, Tabs, Tab, Divider } from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import type { InvestigationReport as IR } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

import React from 'react';

function parseInlineMarkdown(text: string): React.ReactNode[] {
  // Support bold **text**, code `text`, and italic *text* or _text_
  const regex = /(\*\*.*?\*\*|`.*?`|\*.*?\*|_.*?_)/g;
  const parts = text.split(regex);
  return parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return (
        <strong key={index} style={{ color: '#818cf8', fontWeight: 600 }}>
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={index}
          style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.82em',
            background: 'rgba(99, 102, 241, 0.1)',
            padding: '2px 6px',
            borderRadius: '4px',
            color: '#a5b4fc',
            border: '1px solid rgba(99, 102, 241, 0.2)',
          }}
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    if ((part.startsWith('*') && part.endsWith('*')) || (part.startsWith('_') && part.endsWith('_'))) {
      return (
        <em key={index} style={{ fontStyle: 'italic', color: 'rgba(255,255,255,0.7)' }}>
          {part.slice(1, -1)}
        </em>
      );
    }
    return part;
  });
}

function parseMarkdownToBlocks(text: string): React.ReactNode[] {
  if (!text) return [];
  
  const blocks: React.ReactNode[] = [];
  const lines = text.split('\n');
  let inCodeBlock = false;
  let codeBlockLines: string[] = [];
  let currentParagraphLines: string[] = [];

  const flushParagraph = (key: string | number) => {
    if (currentParagraphLines.length > 0) {
      const paragraphText = currentParagraphLines.join('\n');
      blocks.push(
        <Typography
          key={`p-${key}`}
          variant="body1"
          sx={{
            color: 'text.primary',
            lineHeight: 1.85,
            fontSize: '0.92rem',
            mb: 1.5,
            whiteSpace: 'pre-line',
          }}
        >
          {parseInlineMarkdown(paragraphText)}
        </Typography>
      );
      currentParagraphLines = [];
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // 1. Code blocks
    if (trimmed.startsWith('```')) {
      if (inCodeBlock) {
        // End of code block
        const codeText = codeBlockLines.join('\n');
        blocks.push(
          <Box
            key={`code-${i}`}
            component="pre"
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.8rem',
              background: 'rgba(5, 5, 12, 0.9)',
              p: 2,
              borderRadius: 2,
              border: '1px solid rgba(99, 102, 241, 0.2)',
              overflowX: 'auto',
              my: 2,
              color: '#a5b4fc',
            }}
          >
            <code>{codeText}</code>
          </Box>
        );
        codeBlockLines = [];
        inCodeBlock = false;
      } else {
        // Start of code block
        flushParagraph(i);
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockLines.push(line);
      continue;
    }

    // 2. Horizontal rules
    if (trimmed === '---' || trimmed === '***') {
      flushParagraph(i);
      blocks.push(
        <Divider key={`hr-${i}`} sx={{ my: 2.5, borderColor: 'rgba(99, 102, 241, 0.15)' }} />
      );
      continue;
    }

    // 3. Headings
    const headerMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headerMatch) {
      flushParagraph(i);
      const level = headerMatch[1].length;
      const content = headerMatch[2];
      
      let variant: 'h4' | 'h5' | 'h6' | 'subtitle1' | 'body1' = 'body1';
      let color = 'text.primary';
      let fontSize = '1rem';
      let mt = 2;
      let mb = 1;
      let fontWeight = 600;
      
      if (level === 1) {
        variant = 'h4';
        fontSize = '1.3rem';
        fontWeight = 700;
        mt = 3;
        mb = 1.5;
      } else if (level === 2) {
        variant = 'h5';
        color = '#6366f1';
        fontSize = '1.15rem';
        fontWeight = 700;
        mt = 2.5;
        mb = 1;
      } else if (level === 3) {
        variant = 'h6';
        color = '#14b8a6';
        fontSize = '1rem';
        fontWeight = 600;
        mt = 2;
        mb = 1;
      } else {
        variant = 'subtitle1';
        color = '#818cf8';
        fontSize = '0.92rem';
        fontWeight = 600;
        mt = 1.5;
        mb = 0.5;
      }
      
      blocks.push(
        <Typography
          key={`h-${i}`}
          variant={variant}
          sx={{
            fontFamily: '"Space Grotesk", sans-serif',
            fontWeight,
            color,
            mt,
            mb,
            fontSize,
          }}
        >
          {parseInlineMarkdown(content)}
        </Typography>
      );
      continue;
    }

    // 4. Blockquotes
    if (trimmed.startsWith('> ')) {
      flushParagraph(i);
      blocks.push(
        <Box
          key={`quote-${i}`}
          sx={{
            borderLeft: '3px solid #6366f1',
            pl: 2,
            py: 0.5,
            my: 1.5,
            background: 'rgba(99, 102, 241, 0.03)',
            borderRadius: '0 4px 4px 0',
          }}
        >
          <Typography
            variant="body1"
            sx={{
              color: 'text.secondary',
              fontStyle: 'italic',
              lineHeight: 1.8,
              fontSize: '0.92rem',
            }}
          >
            {parseInlineMarkdown(trimmed.slice(2))}
          </Typography>
        </Box>
      );
      continue;
    }

    // 5. Bullet List
    if (trimmed.startsWith('- ') || trimmed.startsWith('* ') || trimmed.startsWith('+ ')) {
      flushParagraph(i);
      blocks.push(
        <Box
          key={`bullet-${i}`}
          component="li"
          sx={{
            color: 'text.primary',
            lineHeight: 1.85,
            fontSize: '0.92rem',
            ml: 3,
            mb: 1,
            display: 'list-item',
            listStyleType: 'disc',
          }}
        >
          {parseInlineMarkdown(trimmed.slice(2))}
        </Box>
      );
      continue;
    }

    // 6. Numbered List
    const numListMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
    if (numListMatch) {
      flushParagraph(i);
      const content = numListMatch[2];
      blocks.push(
        <Box
          key={`num-${i}`}
          component="li"
          sx={{
            color: 'text.primary',
            lineHeight: 1.85,
            fontSize: '0.92rem',
            ml: 3,
            mb: 1,
            display: 'list-item',
            listStyleType: 'decimal',
          }}
        >
          {parseInlineMarkdown(content)}
        </Box>
      );
      continue;
    }

    // 7. Regular paragraph text (accumulate multi-line paragraphs)
    if (trimmed === '') {
      flushParagraph(i);
    } else {
      currentParagraphLines.push(line);
    }
  }

  // Flush any remaining paragraph at the end
  flushParagraph('end');

  return blocks;
}

function ReportText({ text }: { text?: string }) {
  if (!text) return (
    <Typography variant="body2" sx={{ color: 'text.secondary', fontStyle: 'italic', py: 3, textAlign: 'center' }}>
      Report section not yet available
    </Typography>
  );

  const blocks = parseMarkdownToBlocks(text);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      {blocks.map((block, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: Math.min(i * 0.04, 0.8), duration: 0.35 }}
        >
          {block}
        </motion.div>
      ))}
    </Box>
  );
}

interface InvestigationReportProps {
  report?: IR;
}

const TABS = [
  { label: 'Static Summary', key: 'summary' },
  { label: 'Dynamic Analysis', key: 'dynamic_summary' },
  { label: 'Final Report', key: 'final_report' },
];

const InvestigationReport = memo(function InvestigationReport({ report }: InvestigationReportProps) {
  const [tab, setTab] = useState(0);

  const activeKey = TABS[tab].key;
  let content = report?.[activeKey as keyof IR] as string | undefined;

  // Fallback for key mismatches or empty report sections in offline/heuristic scans
  if (!content) {
    if (activeKey === 'dynamic_summary') {
      content = (report as any)?.dynamic_analysis_summary;
    } else if (activeKey === 'final_report') {
      content = (report as any)?.reverse_engineering_summary || (report as any)?.static_analysis_summary;
    }
  }

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.05)',
        }}
      >
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem', mb: 0.5 }}>
          Investigation Report
        </Typography>
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          AI-generated security analysis in plain English
        </Typography>
      </Box>

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{
          px: 3,
          borderBottom: '1px solid rgba(99,102,241,0.1)',
          '& .MuiTab-root': { fontSize: '0.82rem', py: 2, minWidth: 0, px: 2 },
        }}
      >
        {TABS.map((t) => (
          <Tab key={t.key} label={t.label} />
        ))}
      </Tabs>

      <Box sx={{ p: 4 }}>
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
          >
            <ReportText text={content} />
          </motion.div>
        </AnimatePresence>

        {/* Recommendations */}
        {tab === 2 && report?.recommendations && report.recommendations.length > 0 && (
          <Box sx={{ mt: 4, pt: 4, borderTop: '1px solid rgba(99,102,241,0.1)' }}>
            <Typography variant="overline" sx={{ color: '#6366f1', display: 'block', mb: 2, fontSize: '0.65rem' }}>
              RECOMMENDATIONS
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              {report.recommendations.map((rec, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.06 }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      gap: 2,
                      p: 1.5,
                      borderRadius: 2,
                      background: 'rgba(99,102,241,0.05)',
                      border: '1px solid rgba(99,102,241,0.12)',
                    }}
                  >
                    <Typography sx={{ color: '#6366f1', fontWeight: 700, fontSize: '0.85rem', minWidth: 20 }}>
                      {i + 1}.
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'text.secondary', lineHeight: 1.7 }}>
                      {rec}
                    </Typography>
                  </Box>
                </motion.div>
              ))}
            </Box>
          </Box>
        )}
      </Box>
    </GlassCard>
  );
});

export default InvestigationReport;
