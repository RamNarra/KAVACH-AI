'use client';
import React from 'react';
import { Box, Typography, Chip, Button, LinearProgress } from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Videocam as VideoIcon,
  PhotoCamera as ScreenshotIcon,
  Timeline as EventIcon,
  CheckCircle as DoneIcon,
  Error as FailIcon,
  HourglassBottom as RunningIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import type { DynamicAnalysisResult } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface DynamicSandboxPanelProps {
  data?: DynamicAnalysisResult;
  analysisId: string;
}

function StatusBadge({ status }: { status: string }) {
  const configs: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    COMPLETED: { color: '#10b981', icon: <DoneIcon sx={{ fontSize: 16 }} />, label: 'Completed' },
    FAILED: { color: '#ef4444', icon: <FailIcon sx={{ fontSize: 16 }} />, label: 'Failed' },
    RUNNING: { color: '#6366f1', icon: <RunningIcon sx={{ fontSize: 16 }} />, label: 'Running' },
    UNAVAILABLE: { color: '#64748b', icon: null, label: 'Unavailable' },
    UNSUPPORTED_ABI: { color: '#f59e0b', icon: null, label: 'ABI Mismatch' },
  };
  const cfg = configs[status] || configs.UNAVAILABLE;
  return (
    <Chip
      {...(cfg.icon ? { icon: cfg.icon as React.ReactElement } : {})}
      label={cfg.label}
      size="small"
      sx={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: '0.65rem',
        background: `${cfg.color}18`,
        border: `1px solid ${cfg.color}40`,
        color: cfg.color,
      }}
    />
  );
}

export default function DynamicSandboxPanel({ data, analysisId }: DynamicSandboxPanelProps) {
  if (!data) return null;

  const meta = data.run_metadata;
  const hasScreenshot = !!data.current_screenshot;
  const hasVideo = !!data.has_video;
  const events = (data.normalized_events || []) as unknown[];
  const findings = (data.runtime_findings || []) as unknown[];

  const handleOpenVideo = () => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('kavach_token') : '';
    window.open(`/api/analysis/${analysisId}/dynamic/video?token=${token}`, '_blank');
  };

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(20,184,166,0.2)',
          background: 'rgba(20,184,166,0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <PlayIcon sx={{ color: '#14b8a6', fontSize: 22 }} />
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem' }}>
            Dynamic Sandbox
          </Typography>
        </Box>
        <StatusBadge status={data.status} />
      </Box>

      <Box sx={{ p: 3 }}>
        {/* Stats row */}
        {meta && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
            {[
              { label: 'Events', value: meta.event_count ?? data.event_count },
              { label: 'Duration', value: `${meta.duration_seconds ?? 120}s` },
              { label: 'Findings', value: findings.length },
              { label: 'Hook Packs', value: meta.hook_packs?.length ?? 0 },
            ].map((stat) => (
              <Box
                key={stat.label}
                sx={{
                  px: 2,
                  py: 1.5,
                  borderRadius: 2,
                  background: 'rgba(20,184,166,0.06)',
                  border: '1px solid rgba(20,184,166,0.2)',
                  minWidth: 80,
                  textAlign: 'center',
                }}
              >
                <Typography sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700, fontSize: '1.2rem', color: '#14b8a6', lineHeight: 1 }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
                  {stat.label}
                </Typography>
              </Box>
            ))}
          </Box>
        )}

        {/* Live screenshot */}
        <AnimatePresence>
          {hasScreenshot && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.4 }}
            >
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
                  <ScreenshotIcon sx={{ fontSize: 16, color: '#14b8a6' }} />
                  <Typography variant="overline" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>
                    LIVE SCREENSHOT
                  </Typography>
                </Box>
                <Box
                  component="img"
                  src={data.current_screenshot?.startsWith('data:image/') ? data.current_screenshot : `data:image/png;base64,${data.current_screenshot || ''}`}
                  alt="Live sandbox screenshot"
                  sx={{
                    width: '100%',
                    maxHeight: 280,
                    objectFit: 'contain',
                    borderRadius: 2,
                    border: '1px solid rgba(20,184,166,0.2)',
                    background: '#000',
                  }}
                />
              </Box>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Video */}
        {hasVideo && (
          <Box sx={{ mb: 3 }}>
            <Button
              variant="outlined"
              startIcon={<VideoIcon />}
              onClick={handleOpenVideo}
              sx={{
                borderColor: 'rgba(20,184,166,0.4)',
                color: '#14b8a6',
                '&:hover': { background: 'rgba(20,184,166,0.08)', borderColor: '#14b8a6' },
              }}
            >
              Watch Sandbox Recording
            </Button>
          </Box>
        )}

        {/* Error message */}
        {data.error_message && data.status !== 'COMPLETED' && (
          <Box
            sx={{
              p: 2,
              borderRadius: 2,
              background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.25)',
              mb: 3,
            }}
          >
            <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.75rem', color: '#ef4444' }}>
              {data.error_message}
            </Typography>
          </Box>
        )}

        {/* Hook packs */}
        {meta?.hook_packs && meta.hook_packs.length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block', mb: 1.5, fontSize: '0.6rem' }}>
              ACTIVE HOOK PACKS
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {meta.hook_packs.map((pack) => (
                <Chip
                  key={pack}
                  label={pack}
                  size="small"
                  sx={{
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: '0.65rem',
                    background: 'rgba(20,184,166,0.1)',
                    border: '1px solid rgba(20,184,166,0.25)',
                    color: '#14b8a6',
                  }}
                />
              ))}
            </Box>
          </Box>
        )}

        {/* Event count display */}
        {events.length === 0 && data.status !== 'RUNNING' && (
          <Box sx={{ textAlign: 'center', py: 3 }}>
            <EventIcon sx={{ fontSize: 40, color: 'rgba(20,184,166,0.2)', mb: 1 }} />
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              {data.status === 'UNAVAILABLE' ? 'Dynamic sandbox was not available for this scan' : 'No behavioral events captured'}
            </Typography>
          </Box>
        )}
      </Box>
    </GlassCard>
  );
}
