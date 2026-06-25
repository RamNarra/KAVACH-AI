'use client';
import Grid from '@mui/material/Grid';
import { Box, Typography, Chip, Tooltip } from '@mui/material';
import { Security as SecurityIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import type { AttackTechnique } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

const TACTIC_COLORS: Record<string, string> = {
  'Defense Evasion': '#8b5cf6',
  'Collection': '#f59e0b',
  'Command and Control': '#ef4444',
  'Credential Access': '#f97316',
  'Discovery': '#14b8a6',
  'Exfiltration': '#ef4444',
  'Impact': '#f97316',
  'Initial Access': '#6366f1',
  'Lateral Movement': '#8b5cf6',
  'Persistence': '#6366f1',
  'Privilege Escalation': '#f97316',
};

function getTacticColor(tactic: string): string {
  for (const key of Object.keys(TACTIC_COLORS)) {
    if (tactic.toLowerCase().includes(key.toLowerCase())) return TACTIC_COLORS[key];
  }
  return '#6366f1';
}

interface AttackTechniqueMapProps {
  techniques?: AttackTechnique[];
}

export default function AttackTechniqueMap({ techniques }: AttackTechniqueMapProps) {
  if (!techniques || techniques.length === 0) return null;

  // Group by tactic
  const byTactic = techniques.reduce<Record<string, AttackTechnique[]>>((acc, t) => {
    const tactic = t.tactic || 'Other';
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(t);
    return acc;
  }, {});

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.05)',
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
        }}
      >
        <SecurityIcon sx={{ color: '#6366f1', fontSize: 22 }} />
        <Box>
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem' }}>
            MITRE ATT&CK Mapping
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            {techniques.length} technique{techniques.length !== 1 ? 's' : ''} across {Object.keys(byTactic).length} tactic{Object.keys(byTactic).length !== 1 ? 's' : ''}
          </Typography>
        </Box>
      </Box>

      <Box sx={{ p: 3 }}>
        {Object.entries(byTactic).map(([tactic, techs], ti) => {
          const color = getTacticColor(tactic);
          return (
            <motion.div
              key={tactic}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: ti * 0.07 }}
            >
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
                  <Box
                    sx={{
                      width: 3,
                      height: 18,
                      borderRadius: 2,
                      background: color,
                      boxShadow: `0 0 8px ${color}`,
                    }}
                  />
                  <Typography
                    variant="overline"
                    sx={{ color, fontSize: '0.65rem', letterSpacing: '0.1em', fontFamily: '"JetBrains Mono", monospace' }}
                  >
                    {tactic.toUpperCase()}
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {techs.map((tech, i) => (
                    <motion.div key={i} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.97 }}>
                      <Tooltip
                        title={tech.description || tech.name}
                        placement="top"
                      >
                        <Box
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                            px: 2,
                            py: 1,
                            borderRadius: 2,
                            background: `${color}10`,
                            border: `1px solid ${color}30`,
                            cursor: 'default',
                            '&:hover': { background: `${color}1a`, border: `1px solid ${color}55` },
                            transition: 'all 0.2s ease',
                          }}
                        >
                          <Typography
                            sx={{
                              fontFamily: '"JetBrains Mono", monospace',
                              fontSize: '0.65rem',
                              fontWeight: 700,
                              color,
                              letterSpacing: '0.06em',
                            }}
                          >
                            {tech.id}
                          </Typography>
                          <Typography
                            sx={{ fontSize: '0.78rem', color: 'text.primary', fontWeight: 500 }}
                          >
                            {tech.name}
                          </Typography>
                        </Box>
                      </Tooltip>
                    </motion.div>
                  ))}
                </Box>
              </Box>
            </motion.div>
          );
        })}
      </Box>
    </GlassCard>
  );
}
