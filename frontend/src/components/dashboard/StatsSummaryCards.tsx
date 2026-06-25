'use client';
import Grid from '@mui/material/Grid';
import { useEffect, useState } from 'react';
import { Box, Typography, CircularProgress } from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  CheckCircle as SafeIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { getHistory } from '@/lib/api';
import type { HistoryItem } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface Stat {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
  delay: number;
}

export default function StatsSummaryCards() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<Stat[]>([]);

  useEffect(() => {
    getHistory()
      .then((data: HistoryItem[]) => {
        const completed = data.filter((d) => d.status === 'COMPLETED');
        const avgScore = completed.length
          ? Math.round(completed.reduce((a, b) => a + (b.risk_score ?? 0), 0) / completed.length)
          : 0;
        const highRisk = completed.filter((d) => ['HIGH', 'CRITICAL'].includes(d.threat_level ?? '')).length;
        const safe = completed.filter((d) => ['SAFE', 'LOW'].includes(d.threat_level ?? '')).length;

        setStats([
          {
            label: 'Total Scans',
            value: data.length,
            icon: <AssessmentIcon sx={{ fontSize: 24 }} />,
            color: '#6366f1',
            delay: 0,
          },
          {
            label: 'Avg Risk Score',
            value: completed.length ? `${avgScore}/100` : '—',
            icon: <SecurityIcon sx={{ fontSize: 24 }} />,
            color: avgScore >= 60 ? '#ef4444' : avgScore >= 30 ? '#f59e0b' : '#10b981',
            delay: 0.05,
          },
          {
            label: 'High Risk APKs',
            value: highRisk,
            icon: <BugIcon sx={{ fontSize: 24 }} />,
            color: '#ef4444',
            delay: 0.1,
          },
          {
            label: 'Safe APKs',
            value: safe,
            icon: <SafeIcon sx={{ fontSize: 24 }} />,
            color: '#10b981',
            delay: 0.15,
          },
        ]);
      })
      .catch(() => setStats([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
      <CircularProgress size={28} sx={{ color: '#6366f1' }} />
    </Box>
  );

  return (
    <Grid container spacing={2}>
      {stats.map((stat) => (
        <Grid key={stat.label} size={{ xs: 6, md: 3 }}>
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: stat.delay, duration: 0.4 }}
            whileHover={{ y: -2 }}
          >
            <GlassCard sx={{ p: 3, textAlign: 'center' }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2.5,
                  background: `${stat.color}18`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: stat.color,
                  mx: 'auto',
                  mb: 2,
                  boxShadow: `0 0 16px ${stat.color}20`,
                }}
              >
                {stat.icon}
              </Box>
              <Typography
                sx={{
                  fontFamily: '"Space Grotesk", sans-serif',
                  fontSize: '1.8rem',
                  fontWeight: 700,
                  color: stat.color,
                  lineHeight: 1,
                  mb: 0.5,
                }}
              >
                {stat.value}
              </Typography>
              <Typography variant="caption" sx={{ color: 'text.secondary', letterSpacing: '0.05em' }}>
                {stat.label}
              </Typography>
            </GlassCard>
          </motion.div>
        </Grid>
      ))}
    </Grid>
  );
}
