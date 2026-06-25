'use client';
import Grid from '@mui/material/Grid';
import { Box, Typography, Chip, LinearProgress, Tooltip } from '@mui/material';
import { AccountBalance as BankIcon, Warning as WarnIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import type { BankingFraud } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
  INFO: '#6366f1',
};

interface BankingFraudPanelProps {
  data?: BankingFraud;
}

export default function BankingFraudPanel({ data }: BankingFraudPanelProps) {
  if (!data) return null;
  const score = data.fraud_score ?? 0;
  const badges = data.badges ?? [];
  const actions = data.recommended_actions ?? [];
  const scoreColor = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(245,158,11,0.2)',
          background: 'rgba(245,158,11,0.05)',
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
        }}
      >
        <BankIcon sx={{ color: '#f59e0b', fontSize: 22 }} />
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem', flex: 1 }}>
          Banking Fraud Analysis
        </Typography>
        <Box sx={{ textAlign: 'right' }}>
          <Typography sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700, fontSize: '1.4rem', color: scoreColor, lineHeight: 1 }}>
            {score}
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>/ 100</Typography>
        </Box>
      </Box>

      <Box sx={{ p: 3 }}>
        {/* Score bar */}
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>Fraud Score</Typography>
            <Typography variant="caption" sx={{ color: scoreColor, fontFamily: '"JetBrains Mono"', fontWeight: 700 }}>
              {score}/100
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={score}
            sx={{
              height: 8,
              borderRadius: 4,
              background: 'rgba(255,255,255,0.06)',
              '& .MuiLinearProgress-bar': {
                background: `linear-gradient(90deg, ${scoreColor}80, ${scoreColor})`,
                borderRadius: 4,
              },
            }}
          />
        </Box>

        {/* Badges */}
        {badges.length > 0 && (
          <>
            <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block', mb: 2, fontSize: '0.6rem' }}>
              FRAUD INDICATORS ({badges.length})
            </Typography>
            <Grid container spacing={1.5} sx={{ mb: 3 }}>
              {badges.map((badge, i) => {
                const color = SEVERITY_COLORS[(badge.severity || 'INFO').toUpperCase()] || '#6366f1';
                return (
                  <Grid key={i} size={{ xs: 12, sm: 6 }}>
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.05 }}
                    >
                      <Tooltip title={badge.details?.join(' ') || badge.summary || ''}>
                        <Box
                          sx={{
                            p: 2,
                            borderRadius: 2,
                            background: `${color}0d`,
                            border: `1px solid ${color}30`,
                            cursor: 'default',
                            '&:hover': { background: `${color}15`, border: `1px solid ${color}50` },
                            transition: 'all 0.2s ease',
                          }}
                        >
                          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
                            <WarnIcon sx={{ color, fontSize: 18, mt: 0.2, flexShrink: 0 }} />
                            <Box>
                              <Typography sx={{ fontWeight: 700, fontSize: '0.78rem', color, mb: 0.3, lineHeight: 1.2 }}>
                                {badge.title}
                              </Typography>
                              <Typography variant="caption" sx={{ color: 'text.secondary', lineHeight: 1.5, display: 'block' }}>
                                {badge.summary}
                              </Typography>
                              <Chip
                                label={badge.severity || 'INFO'}
                                size="small"
                                sx={{
                                  mt: 0.8,
                                  fontFamily: '"JetBrains Mono", monospace',
                                  fontSize: '0.58rem',
                                  background: `${color}18`,
                                  color,
                                  border: 'none',
                                  height: 18,
                                }}
                              />
                            </Box>
                          </Box>
                        </Box>
                      </Tooltip>
                    </motion.div>
                  </Grid>
                );
              })}
            </Grid>
          </>
        )}

        {/* Recommended actions */}
        {actions.length > 0 && (
          <>
            <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block', mb: 1.5, fontSize: '0.6rem' }}>
              RECOMMENDED ACTIONS
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {actions.map((action, i) => (
                <Box
                  key={i}
                  sx={{
                    display: 'flex',
                    gap: 1.5,
                    p: 1.5,
                    borderRadius: 2,
                    background: 'rgba(245,158,11,0.05)',
                    border: '1px solid rgba(245,158,11,0.15)',
                  }}
                >
                  <Typography sx={{ color: '#f59e0b', fontWeight: 700, fontSize: '0.8rem', minWidth: 18 }}>
                    •
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.6 }}>
                    {action}
                  </Typography>
                </Box>
              ))}
            </Box>
          </>
        )}

        {badges.length === 0 && (
          <Box sx={{ textAlign: 'center', py: 3 }}>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              No banking fraud indicators detected
            </Typography>
          </Box>
        )}
      </Box>
    </GlassCard>
  );
}
