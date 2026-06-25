'use client';
import { Chip } from '@mui/material';
import type { ThreatLevel } from '@/lib/types';
import { THREAT_COLORS } from './KavachTheme';

interface ThreatBadgeProps {
  level?: ThreatLevel | string;
  size?: 'small' | 'medium';
}

const THREAT_LABELS: Record<string, string> = {
  SAFE: '● SAFE',
  LOW: '● LOW',
  MEDIUM: '⚠ MEDIUM',
  HIGH: '⚠ HIGH',
  CRITICAL: '⛔ CRITICAL',
};

export default function ThreatBadge({ level = 'SAFE', size = 'small' }: ThreatBadgeProps) {
  const color = THREAT_COLORS[level] || '#64748b';
  const label = THREAT_LABELS[level] || level;

  return (
    <Chip
      label={label}
      size={size}
      sx={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: size === 'medium' ? '0.8rem' : '0.65rem',
        fontWeight: 700,
        letterSpacing: '0.08em',
        color,
        background: `${color}18`,
        border: `1px solid ${color}50`,
        boxShadow: `0 0 10px ${color}30`,
        py: size === 'medium' ? 1.5 : 0,
        '& .MuiChip-label': { px: size === 'medium' ? 2 : 1 },
      }}
    />
  );
}
