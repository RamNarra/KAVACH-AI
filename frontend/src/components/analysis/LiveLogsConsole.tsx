'use client';
import { useEffect, useRef, memo } from 'react';
import { Box, Typography } from '@mui/material';
import { motion } from 'framer-motion';
import GlassCard from '@/components/ui/GlassCard';

interface LiveLogsConsoleProps {
  logs: string[];
}

const LiveLogsConsole = memo(function LiveLogsConsole({ logs }: LiveLogsConsoleProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogColor = (log: string) => {
    const l = log.toUpperCase();
    if (l.includes('ERROR') || l.includes('FAIL')) return '#ef4444'; // Red
    if (l.includes('WARN') || l.includes('LIMIT')) return '#f59e0b'; // Amber
    if (l.includes('COMPLETED') || l.includes('SUCCESS')) return '#10b981'; // Green
    if (l.includes('[PIPELINE]')) return '#818cf8'; // Indigo
    if (l.includes('[JADX]') || l.includes('[ANDROGUARD]') || l.includes('[APKiD]')) return '#14b8a6'; // Teal
    return '#94a3b8'; // Slate
  };

  return (
    <GlassCard sx={{ p: 0, height: '480px', display: 'flex', flexDirection: 'column' }}>
      {/* Console Header */}
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <motion.div
            animate={{ opacity: [1, 0.4, 1] }}
            transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          >
            <Box
              sx={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#10b981',
                boxShadow: '0 0 8px #10b981',
              }}
            />
          </motion.div>
          <Typography
            variant="h6"
            sx={{
              fontFamily: '"Space Grotesk", sans-serif',
              fontWeight: 600,
              fontSize: '0.95rem',
              letterSpacing: '0.05em',
            }}
          >
            LIVE ANALYSIS STREAM
          </Typography>
        </Box>
        <Typography
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.72rem',
            color: 'text.secondary',
          }}
        >
          CONSOLE_ACTIVE
        </Typography>
      </Box>

      {/* Terminal View */}
      <Box
        ref={containerRef}
        sx={{
          flex: 1,
          overflowY: 'auto',
          background: 'rgba(5, 5, 12, 0.8)',
          p: 3,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: '0.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: 0.8,
          scrollBehavior: 'smooth',
          // Custom scrollbar
          '&::-webkit-scrollbar': {
            width: '6px',
          },
          '&::-webkit-scrollbar-track': {
            background: 'rgba(255, 255, 255, 0.01)',
          },
          '&::-webkit-scrollbar-thumb': {
            background: 'rgba(99, 102, 241, 0.2)',
            borderRadius: '3px',
          },
          '&::-webkit-scrollbar-thumb:hover': {
            background: 'rgba(99, 102, 241, 0.4)',
          },
        }}
      >
        {logs.map((log, i) => {
          const isLast = i === logs.length - 1;
          const content = (
            <Box sx={{ display: 'flex', gap: 1.5 }}>
              {/* Line number */}
              <Typography
                sx={{
                  fontFamily: 'inherit',
                  fontSize: 'inherit',
                  color: 'rgba(255,255,255,0.15)',
                  userSelect: 'none',
                  minWidth: '24px',
                  textAlign: 'right',
                }}
              >
                {(i + 1).toString().padStart(3, '0')}
              </Typography>
              
              {/* Log Content */}
              <Typography
                sx={{
                  fontFamily: 'inherit',
                  fontSize: 'inherit',
                  color: getLogColor(log),
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {log}
              </Typography>
            </Box>
          );

          if (isLast) {
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.2 }}
              >
                {content}
              </motion.div>
            );
          }

          return (
            <div key={i}>
              {content}
            </div>
          );
        })}
      </Box>
    </GlassCard>
  );
});

export default LiveLogsConsole;
