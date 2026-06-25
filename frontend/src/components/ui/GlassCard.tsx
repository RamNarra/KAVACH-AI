'use client';
import { Box, type BoxProps } from '@mui/material';
import { motion } from 'framer-motion';

interface GlassCardProps extends BoxProps {
  glowColor?: string;
  animate?: boolean;
  children?: React.ReactNode;
}

export default function GlassCard({ glowColor, animate = false, children, sx, ...rest }: GlassCardProps) {
  const content = (
    <Box
      sx={{
        background: 'rgba(15,15,26,0.75)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: '1px solid rgba(99,102,241,0.18)',
        borderRadius: 3,
        boxShadow: glowColor
          ? `0 4px 40px rgba(0,0,0,0.4), 0 0 30px ${glowColor}`
          : '0 4px 40px rgba(0,0,0,0.4)',
        transition: 'box-shadow 0.3s ease, border-color 0.3s ease',
        '&:hover': glowColor
          ? {
              borderColor: glowColor,
              boxShadow: `0 8px 60px rgba(0,0,0,0.5), 0 0 50px ${glowColor}`,
            }
          : {
              borderColor: 'rgba(99,102,241,0.35)',
              boxShadow: '0 8px 60px rgba(0,0,0,0.5), 0 0 20px rgba(99,102,241,0.1)',
            },
        ...sx,
      }}
      {...rest}
    >
      {children}
    </Box>
  );

  if (animate) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        style={{ height: '100%' }}
      >
        {content}
      </motion.div>
    );
  }

  return content;
}
