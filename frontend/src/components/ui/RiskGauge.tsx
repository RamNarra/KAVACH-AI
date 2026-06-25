'use client';
import { Box, Typography } from '@mui/material';
import { RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts';
import { motion } from 'framer-motion';
import { THREAT_COLORS } from './KavachTheme';
import type { ThreatLevel } from '@/lib/types';

interface RiskGaugeProps {
  score: number;
  threatLevel?: ThreatLevel | string;
  size?: number;
  showLabel?: boolean;
}

export default function RiskGauge({ score, threatLevel, size = 180, showLabel = true }: RiskGaugeProps) {
  const level = threatLevel || (
    score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'LOW' : 'SAFE'
  );
  const color = THREAT_COLORS[level] || '#10b981';
  const data = [{ value: score, fill: color }];
  const halfSize = size / 2;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      style={{ position: 'relative', width: size, height: size }}
    >
      <RadialBarChart
        width={size}
        height={size}
        cx={halfSize}
        cy={halfSize}
        innerRadius={halfSize * 0.65}
        outerRadius={halfSize * 0.9}
        data={data}
        startAngle={230}
        endAngle={-50}
        barSize={size * 0.06}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar
          background={{ fill: 'rgba(255,255,255,0.05)' }}
          dataKey="value"
          angleAxisId={0}
          fill={color}
          cornerRadius={size * 0.03}
          style={{ filter: `drop-shadow(0 0 ${size * 0.05}px ${color})` }}
        />
      </RadialBarChart>

      {showLabel && (
        <Box
          sx={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none',
          }}
        >
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4, duration: 0.4 }}
          >
            <Typography
              sx={{
                fontFamily: '"Space Grotesk", sans-serif',
                fontSize: size * 0.2,
                fontWeight: 700,
                color,
                lineHeight: 1,
                textShadow: `0 0 20px ${color}`,
                textAlign: 'center',
              }}
            >
              {score}
            </Typography>
            <Typography
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: size * 0.065,
                color: 'text.secondary',
                textAlign: 'center',
                letterSpacing: '0.08em',
                mt: 0.5,
              }}
            >
              / 100
            </Typography>
          </motion.div>
        </Box>
      )}
    </motion.div>
  );
}
