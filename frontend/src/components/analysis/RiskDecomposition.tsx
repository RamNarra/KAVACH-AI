'use client';
import Grid from '@mui/material/Grid';
import { Box, Typography, LinearProgress, Chip } from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { motion } from 'framer-motion';
import type { RiskDecomposition } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface RiskDecompositionPanelProps {
  data?: RiskDecomposition;
}

function ScoreBar({ label, value, color, delay }: { label: string; value: number; color: string; delay: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay, duration: 0.4 }}
    >
      <Box sx={{ mb: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.7 }}>
          <Typography sx={{ fontSize: '0.82rem', fontWeight: 500, color: 'text.secondary' }}>{label}</Typography>
          <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.82rem', fontWeight: 700, color }}>
            {value ?? 0}
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={value ?? 0}
          sx={{
            height: 6,
            borderRadius: 3,
            background: 'rgba(255,255,255,0.06)',
            '& .MuiLinearProgress-bar': {
              background: `linear-gradient(90deg, ${color}70, ${color})`,
              borderRadius: 3,
            },
          }}
        />
      </Box>
    </motion.div>
  );
}

const SCORE_CONFIGS = [
  { key: 'static_score', label: 'Static Analysis', color: '#6366f1' },
  { key: 'dynamic_score', label: 'Dynamic Sandbox', color: '#14b8a6' },
  { key: 'ai_score', label: 'AI Assessment', color: '#8b5cf6' },
  { key: 'fraud_score', label: 'Banking Fraud', color: '#f59e0b' },
  { key: 'ml_score', label: 'ML Classifier', color: '#10b981' },
];

export default function RiskDecompositionPanel({ data }: RiskDecompositionPanelProps) {
  if (!data) return null;

  const getScore = (key: string): number => {
    const rawData = data as any;
    if (rawData[key] !== undefined) return rawData[key] ?? 0;
    const compKey = key.replace('_score', '');
    const mappedKey = compKey === 'fraud' ? 'banking_fraud' : compKey;
    return rawData.components?.[mappedKey] ?? 0;
  };

  const chartData = SCORE_CONFIGS.map((cfg) => ({
    name: cfg.label.split(' ')[0],
    score: getScore(cfg.key),
    color: cfg.color,
  }));

  const composite = data.composite_score ?? 0;
  const compositeColor = composite >= 70 ? '#ef4444' : composite >= 40 ? '#f59e0b' : '#10b981';
  const topContributors = (data as any).top_contributors || [];

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
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
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem' }}>
          Risk Decomposition
        </Typography>
        <Box sx={{ textAlign: 'right' }}>
          <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, fontSize: '1.3rem', color: compositeColor, lineHeight: 1 }}>
            {composite}
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>composite</Typography>
        </Box>
      </Box>

      <Box sx={{ p: 3 }}>
        <Grid container spacing={3} sx={{ alignItems: 'center' }}>
          {/* Bar chart */}
          <Grid size={{ xs: 12, sm: 5 }}>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={chartData} margin={{ top: 4, right: 4, bottom: 4, left: -20 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#64748b', fontSize: 9, fontFamily: '"JetBrains Mono", monospace' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 9 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(10,10,15,0.95)',
                    border: '1px solid rgba(99,102,241,0.3)',
                    borderRadius: 8,
                    fontSize: 11,
                    color: '#e2e8f0',
                  }}
                  formatter={(value: any) => [`${value}/100`, 'Score']}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Grid>

          {/* Score bars */}
          <Grid size={{ xs: 12, sm: 7 }}>
            {SCORE_CONFIGS.map((cfg, i) => (
              <ScoreBar
                key={cfg.key}
                label={cfg.label}
                value={getScore(cfg.key)}
                color={cfg.color}
                delay={i * 0.05}
              />
            ))}
          </Grid>
        </Grid>

        {/* Contributors List */}
        {topContributors.length > 0 && (
          <Box sx={{ mt: 3, pt: 2.5, borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <Typography variant="subtitle2" sx={{ fontSize: '0.8rem', fontWeight: 600, color: 'text.secondary', mb: 1.5 }}>
              Key Risk Contributors
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {topContributors.map((c: any, idx: number) => (
                <Chip
                  key={idx}
                  label={`${c.label} (+${c.weight})`}
                  size="small"
                  variant="outlined"
                  sx={{
                    fontSize: '0.7rem',
                    borderColor: 'rgba(239, 68, 68, 0.2)',
                    color: '#fca5a5',
                    background: 'rgba(239, 68, 68, 0.04)',
                    fontWeight: 500,
                  }}
                />
              ))}
            </Box>
          </Box>
        )}
      </Box>
    </GlassCard>
  );
}
