'use client';
import Grid from '@mui/material/Grid';
import { Box, Container, Typography, Button, Chip } from '@mui/material';
import {
  Shield as ShieldIcon,
  Psychology as AIIcon,
  BugReport as BugIcon,
  AccountBalance as BankIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  ArrowForward as ArrowIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';
import { motion, useScroll, useTransform } from 'framer-motion';
import { useRef, useEffect, useState } from 'react';
import Link from 'next/link';
import PageTransition from '@/components/ui/PageTransition';
import GlassCard from '@/components/ui/GlassCard';

const FEATURES = [
  {
    icon: <ShieldIcon sx={{ fontSize: 32 }} />,
    title: 'Static Analysis',
    desc: 'Deep JADX decompilation, permission audit, manifest forensics, hardcoded secrets, and YARA rule matching.',
    color: '#6366f1',
    delay: 0.1,
  },
  {
    icon: <BugIcon sx={{ fontSize: 32 }} />,
    title: 'Dynamic Sandbox',
    desc: '14-step automated interaction playbook runs inside an Android emulator — capturing real runtime behavior.',
    color: '#14b8a6',
    delay: 0.2,
  },
  {
    icon: <AIIcon sx={{ fontSize: 32 }} />,
    title: 'Gemini AI',
    desc: 'Google Gemini synthesizes a plain-English storytelling security report with calming, actionable guidance.',
    color: '#8b5cf6',
    delay: 0.3,
  },
  {
    icon: <BankIcon sx={{ fontSize: 32 }} />,
    title: 'Banking Fraud',
    desc: 'Specialized engine detects overlay attacks, credential harvesting, SMS interception, and UPI fraud.',
    color: '#f59e0b',
    delay: 0.4,
  },
  {
    icon: <SecurityIcon sx={{ fontSize: 32 }} />,
    title: 'MITRE ATT&CK',
    desc: 'Every finding is mapped to MITRE ATT&CK for Mobile framework techniques and tactics.',
    color: '#ef4444',
    delay: 0.5,
  },
  {
    icon: <SpeedIcon sx={{ fontSize: 32 }} />,
    title: 'Real-time Updates',
    desc: 'Live SSE streaming shows analysis progress step-by-step as Kavach works through the pipeline.',
    color: '#10b981',
    delay: 0.6,
  },
];

const STATS = [
  { value: '10+', label: 'Analyzers' },
  { value: '24', label: 'MITRE Techniques' },
  { value: '500MB', label: 'Max APK Size' },
  { value: '120s', label: 'Dynamic Runtime' },
];

function OrbitalRings() {
  return (
    <Box sx={{ position: 'relative', width: 320, height: 320, mx: 'auto' }}>
      {/* Core shield */}
      <motion.div
        style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
        animate={{ scale: [1, 1.05, 1] }}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
      >
        <Box
          sx={{
            width: 100,
            height: 100,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 60px rgba(99,102,241,0.6), 0 0 120px rgba(99,102,241,0.2)',
          }}
        >
          <ShieldIcon sx={{ fontSize: 48, color: '#fff' }} />
        </Box>
      </motion.div>

      {/* Ring 1 */}
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          style={{
            position: 'absolute',
            inset: i * 40,
            borderRadius: '50%',
            border: `1px solid rgba(99,102,241,${0.3 - i * 0.08})`,
          }}
          animate={{ rotate: i % 2 === 0 ? 360 : -360 }}
          transition={{ duration: 8 + i * 4, repeat: Infinity, ease: 'linear' }}
        >
          {/* Dot on ring */}
          <Box
            sx={{
              position: 'absolute',
              top: -4,
              left: '50%',
              transform: 'translateX(-50%)',
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: i === 0 ? '#6366f1' : i === 1 ? '#14b8a6' : '#8b5cf6',
              boxShadow: `0 0 10px ${i === 0 ? '#6366f1' : i === 1 ? '#14b8a6' : '#8b5cf6'}`,
            }}
          />
        </motion.div>
      ))}
    </Box>
  );
}

function StatCounter({ value, label, delay }: { value: string; label: string; delay: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5 }}
    >
      <Box sx={{ textAlign: 'center' }}>
        <Typography
          sx={{
            fontFamily: '"Space Grotesk", sans-serif',
            fontSize: { xs: '2rem', md: '2.5rem' },
            fontWeight: 700,
            background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            lineHeight: 1,
          }}
        >
          {value}
        </Typography>
        <Typography variant="body2" sx={{ mt: 0.5, color: 'text.secondary', fontSize: '0.8rem', letterSpacing: '0.05em' }}>
          {label}
        </Typography>
      </Box>
    </motion.div>
  );
}

export default function LandingPage() {
  const heroRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: heroRef, offset: ['start start', 'end start'] });
  const heroY = useTransform(scrollYProgress, [0, 1], [0, -60]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.7], [1, 0]);

  return (
    <PageTransition>
      <Box sx={{ position: 'relative', minHeight: '100vh', overflow: 'hidden' }}>

        {/* ── Hero ─────────────────────────────────────────────────────── */}
        <Box ref={heroRef} sx={{ pt: { xs: 14, md: 18 }, pb: { xs: 8, md: 14 }, position: 'relative', zIndex: 1 }}>
          <motion.div style={{ y: heroY, opacity: heroOpacity }}>
            <Container maxWidth="lg">
              <Grid container spacing={6} sx={{ alignItems: 'center' }}>

                {/* Left: Text */}
                <Grid size={{ xs: 12, md: 6 }}>
                  <motion.div
                    initial={{ opacity: 0, x: -40 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
                  >
                    <Chip
                      label="Powered by Google Gemini AI"
                      size="small"
                      sx={{
                        mb: 3,
                        background: 'rgba(99,102,241,0.15)',
                        border: '1px solid rgba(99,102,241,0.35)',
                        color: '#818cf8',
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: '0.7rem',
                        letterSpacing: '0.06em',
                      }}
                    />

                    <Typography
                      component="h1"
                      sx={{
                        fontFamily: '"Space Grotesk", sans-serif',
                        fontSize: { xs: '2.6rem', sm: '3.5rem', md: '4rem' },
                        fontWeight: 700,
                        lineHeight: 1.1,
                        letterSpacing: '-0.02em',
                        mb: 3,
                      }}
                    >
                      Scan. Detect.{' '}
                      <Box
                        component="span"
                        sx={{
                          background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
                          WebkitBackgroundClip: 'text',
                          WebkitTextFillColor: 'transparent',
                        }}
                      >
                        Protect.
                      </Box>
                    </Typography>

                    <Typography
                      variant="body1"
                      sx={{ color: 'text.secondary', mb: 4, fontSize: '1.05rem', maxWidth: 480, lineHeight: 1.8 }}
                    >
                      Upload any Android APK and get a comprehensive AI-powered security report —
                      detecting malware, banking fraud, and MITRE ATT&CK techniques in seconds.
                    </Typography>

                    {/* Feature bullets */}
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, mb: 5 }}>
                      {['Static + Dynamic dual-engine analysis', 'Banking fraud badge detection', 'Plain-English AI storytelling reports'].map((feat) => (
                        <Box key={feat} sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                          <CheckIcon sx={{ color: '#10b981', fontSize: 18 }} />
                          <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.9rem' }}>
                            {feat}
                          </Typography>
                        </Box>
                      ))}
                    </Box>

                    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                      <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}>
                        <Button
                          component={Link}
                          href="/register"
                          variant="contained"
                          size="large"
                          endIcon={<ArrowIcon />}
                          sx={{ px: 4, py: 1.5, fontSize: '1rem', borderRadius: 2.5 }}
                        >
                          Start Scanning Free
                        </Button>
                      </motion.div>
                      <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}>
                        <Button
                          component={Link}
                          href="/login"
                          variant="outlined"
                          size="large"
                          sx={{ px: 4, py: 1.5, fontSize: '1rem', borderRadius: 2.5 }}
                        >
                          Sign in
                        </Button>
                      </motion.div>
                    </Box>
                  </motion.div>
                </Grid>

                {/* Right: Orbital animation */}
                <Grid size={{ xs: 12, md: 6 }}>
                  <motion.div
                    initial={{ opacity: 0, scale: 0.85 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.8, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  >
                    <OrbitalRings />
                  </motion.div>
                </Grid>

              </Grid>
            </Container>
          </motion.div>
        </Box>

        {/* ── Stats strip ──────────────────────────────────────────────── */}
        <Box sx={{ py: 6, position: 'relative', zIndex: 1 }}>
          <Container maxWidth="md">
            <GlassCard sx={{ p: 4 }}>
              <Grid container spacing={4} sx={{ justifyContent: 'center' }}>
                {STATS.map((stat, i) => (
                  <Grid key={stat.label} size={{ xs: 6, sm: 3 }}>
                    <StatCounter value={stat.value} label={stat.label} delay={i * 0.1} />
                  </Grid>
                ))}
              </Grid>
            </GlassCard>
          </Container>
        </Box>

        {/* ── Features grid ────────────────────────────────────────────── */}
        <Box sx={{ py: { xs: 8, md: 12 }, position: 'relative', zIndex: 1 }}>
          <Container maxWidth="lg">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.6 }}
            >
              <Box sx={{ textAlign: 'center', mb: 8 }}>
                <Typography variant="overline" sx={{ color: '#6366f1', mb: 2, display: 'block' }}>
                  PLATFORM CAPABILITIES
                </Typography>
                <Typography
                  component="h2"
                  sx={{
                    fontFamily: '"Space Grotesk", sans-serif',
                    fontSize: { xs: '2rem', md: '2.8rem' },
                    fontWeight: 700,
                    letterSpacing: '-0.02em',
                    mb: 2,
                  }}
                >
                  Everything you need to{' '}
                  <Box component="span" sx={{ color: '#6366f1' }}>analyze threats</Box>
                </Typography>
                <Typography variant="body1" sx={{ color: 'text.secondary', maxWidth: 560, mx: 'auto' }}>
                  KAVACH AI combines multiple analysis engines, AI synthesis, and real-time behavioral tracing
                  into a single unified security platform.
                </Typography>
              </Box>
            </motion.div>

            <Grid container spacing={3}>
              {FEATURES.map((feature) => (
                <Grid key={feature.title} size={{ xs: 12, sm: 6, md: 4 }}>
                  <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true, margin: '-60px' }}
                    transition={{ delay: feature.delay, duration: 0.5 }}
                    whileHover={{ y: -4 }}
                  >
                    <GlassCard sx={{ p: 3.5, height: '100%' }}>
                      <Box
                        sx={{
                          width: 56,
                          height: 56,
                          borderRadius: 2.5,
                          background: `${feature.color}18`,
                          border: `1px solid ${feature.color}30`,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: feature.color,
                          mb: 2.5,
                          boxShadow: `0 0 20px ${feature.color}20`,
                        }}
                      >
                        {feature.icon}
                      </Box>
                      <Typography
                        variant="h6"
                        sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, mb: 1.5, fontSize: '1.05rem' }}
                      >
                        {feature.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: 'text.secondary', lineHeight: 1.7 }}>
                        {feature.desc}
                      </Typography>
                    </GlassCard>
                  </motion.div>
                </Grid>
              ))}
            </Grid>
          </Container>
        </Box>

        {/* ── CTA section ──────────────────────────────────────────────── */}
        <Box sx={{ py: { xs: 10, md: 16 }, position: 'relative', zIndex: 1 }}>
          <Container maxWidth="md">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
            >
              <GlassCard
                sx={{
                  p: { xs: 5, md: 8 },
                  textAlign: 'center',
                  background: 'linear-gradient(135deg, rgba(99,102,241,0.1) 0%, rgba(20,184,166,0.05) 100%)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  position: 'relative',
                  overflow: 'hidden',
                }}
              >
                {/* Glow accent */}
                <Box
                  sx={{
                    position: 'absolute',
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%,-50%)',
                    width: 400,
                    height: 400,
                    borderRadius: '50%',
                    background: 'radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 70%)',
                    pointerEvents: 'none',
                  }}
                />
                <Typography variant="overline" sx={{ color: '#6366f1', mb: 2, display: 'block' }}>
                  GET STARTED TODAY
                </Typography>
                <Typography
                  component="h2"
                  sx={{
                    fontFamily: '"Space Grotesk", sans-serif',
                    fontSize: { xs: '2rem', md: '2.8rem' },
                    fontWeight: 700,
                    letterSpacing: '-0.02em',
                    mb: 2,
                  }}
                >
                  Ready to secure your app?
                </Typography>
                <Typography variant="body1" sx={{ color: 'text.secondary', mb: 5, maxWidth: 440, mx: 'auto' }}>
                  Create a free account and upload your first APK. Get a full security report in under 2 minutes.
                </Typography>
                <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}>
                  <Button
                    component={Link}
                    href="/register"
                    variant="contained"
                    size="large"
                    endIcon={<ArrowIcon />}
                    sx={{ px: 5, py: 1.8, fontSize: '1.05rem', borderRadius: 2.5 }}
                  >
                    Create Free Account
                  </Button>
                </motion.div>
              </GlassCard>
            </motion.div>
          </Container>
        </Box>

        {/* Footer */}
        <Box sx={{ py: 4, borderTop: '1px solid rgba(99,102,241,0.1)', position: 'relative', zIndex: 1 }}>
          <Container maxWidth="lg">
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                © 2026 KAVACH AI — Built for IIT Hyderabad Hackathon
              </Typography>
              <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: '"JetBrains Mono", monospace' }}>
                POWERED BY GOOGLE GEMINI
              </Typography>
            </Box>
          </Container>
        </Box>

      </Box>
    </PageTransition>
  );
}
