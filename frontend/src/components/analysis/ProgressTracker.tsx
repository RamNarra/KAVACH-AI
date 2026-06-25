'use client';
import { Box, Typography, LinearProgress, Chip, CircularProgress } from '@mui/material';
import {
  CheckCircle as DoneIcon,
  RadioButtonUnchecked as PendingIcon,
  Error as FailIcon,
  FiberManualRecord as RunningDot,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { memo } from 'react';
import type { ScanProgress } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

const STEPS = [
  { key: 'download', label: 'Download', desc: 'Fetching the APK file' },
  { key: 'jadx', label: 'JADX Decompile', desc: 'Decompiling Java bytecode' },
  { key: 'androguard', label: 'Androguard', desc: 'Static manifest & code analysis' },
  { key: 'gemini', label: 'AI Synthesis', desc: 'Gemini writing security report' },
  { key: 'finalize', label: 'Finalize', desc: 'Saving results to database' },
];

const DYNAMIC_STEPS = [
  { key: 'dynamic_sandbox', label: 'Dynamic Sandbox', desc: 'Running behavioral trace in emulator' },
];

type StepStatus = 'COMPLETED' | 'RUNNING' | 'WAITING' | 'FAILED' | string;

function StepIcon({ status }: { status: StepStatus }) {
  if (status === 'COMPLETED') return <DoneIcon sx={{ color: '#10b981', fontSize: 20 }} />;
  if (status === 'RUNNING') return (
    <motion.div animate={{ rotate: 360 }} transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}>
      <CircularProgress size={18} sx={{ color: '#6366f1' }} />
    </motion.div>
  );
  if (status === 'FAILED') return <FailIcon sx={{ color: '#ef4444', fontSize: 20 }} />;
  return <PendingIcon sx={{ color: '#334155', fontSize: 20 }} />;
}

function StepRow({ label, desc, status }: { label: string; desc: string; status: StepStatus }) {
  const isRunning = status === 'RUNNING';
  const isDone = status === 'COMPLETED';
  const isFailed = status === 'FAILED';

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          p: 1.5,
          borderRadius: 2,
          background: isRunning ? 'rgba(99,102,241,0.08)' : 'transparent',
          border: isRunning ? '1px solid rgba(99,102,241,0.2)' : '1px solid transparent',
          transition: 'all 0.3s ease',
          mb: 0.5,
        }}
      >
        <StepIcon status={status} />
        <Box sx={{ flex: 1 }}>
          <Typography
            sx={{
              fontSize: '0.875rem',
              fontWeight: isRunning ? 600 : isDone ? 500 : 400,
              color: isRunning ? '#818cf8' : isDone ? 'text.primary' : isFailed ? '#ef4444' : 'text.secondary',
              lineHeight: 1,
              mb: 0.3,
            }}
          >
            {label}
          </Typography>
          <Typography sx={{ fontSize: '0.72rem', color: 'text.secondary', lineHeight: 1 }}>
            {desc}
          </Typography>
        </Box>
        <Chip
          size="small"
          label={status || 'WAITING'}
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.6rem',
            letterSpacing: '0.08em',
            background: isRunning ? 'rgba(99,102,241,0.2)' : isDone ? 'rgba(16,185,129,0.15)' : isFailed ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.04)',
            color: isRunning ? '#818cf8' : isDone ? '#10b981' : isFailed ? '#ef4444' : '#64748b',
            border: 'none',
          }}
        />
      </Box>
    </motion.div>
  );
}

interface ProgressTrackerProps {
  progress?: ScanProgress;
  status: string;
}

const ProgressTracker = memo(
  function ProgressTracker({ progress = {}, status }: ProgressTrackerProps) {
    const allSteps = [...STEPS, ...DYNAMIC_STEPS];
    const completedCount = allSteps.filter((s) => (progress as Record<string, string>)[s.key] === 'COMPLETED').length;
    const totalSteps = allSteps.filter((s) => (progress as Record<string, string>)[s.key] !== undefined).length || STEPS.length;
    const pct = totalSteps > 0 ? Math.round((completedCount / totalSteps) * 100) : 0;

    const hasDynamic = !!progress?.dynamic_sandbox;

    return (
      <GlassCard sx={{ p: 0, overflow: 'hidden' }}>
        {/* Header */}
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
            {status === 'PROCESSING' && (
              <motion.div animate={{ scale: [1, 1.3, 1] }} transition={{ duration: 1.5, repeat: Infinity }}>
                <RunningDot sx={{ color: '#6366f1', fontSize: 12 }} />
              </motion.div>
            )}
            <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '0.95rem' }}>
              Analysis Progress
            </Typography>
          </Box>
          <Typography
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.8rem',
              color: '#6366f1',
              fontWeight: 700,
            }}
          >
            {pct}%
          </Typography>
        </Box>

        {/* Progress bar */}
        <LinearProgress
          variant="determinate"
          value={pct}
          sx={{ borderRadius: 0, height: 3, background: 'rgba(255,255,255,0.05)' }}
        />

        <Box sx={{ p: 3 }}>
          {/* Static steps */}
          <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block', mb: 1.5, fontSize: '0.6rem' }}>
            STATIC PIPELINE
          </Typography>
          {STEPS.map((step) => (
            <StepRow
              key={step.key}
              label={step.label}
              desc={step.desc}
              status={(progress as Record<string, string>)[step.key] || 'WAITING'}
            />
          ))}

          {/* Dynamic steps (only if triggered) */}
          {hasDynamic && (
            <>
              <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block', mt: 2.5, mb: 1.5, fontSize: '0.6rem' }}>
                DYNAMIC SANDBOX
              </Typography>
              {DYNAMIC_STEPS.map((step) => (
                <StepRow
                  key={step.key}
                  label={step.label}
                  desc={step.desc}
                  status={(progress as Record<string, string>)[step.key] || 'WAITING'}
                />
              ))}
            </>
          )}

        </Box>
      </GlassCard>
    );
  },
  (prevProps, nextProps) => {
    if (prevProps.status !== nextProps.status) return false;
    const prevKeys = Object.keys(prevProps.progress || {});
    const nextKeys = Object.keys(nextProps.progress || {});
    if (prevKeys.length !== nextKeys.length) return false;
    for (const key of prevKeys) {
      if ((prevProps.progress as any)[key] !== (nextProps.progress as any)[key]) {
        return false;
      }
    }
    return true;
  }
);

export default ProgressTracker;
