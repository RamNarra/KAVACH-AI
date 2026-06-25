'use client';
import { useState } from 'react';
import {
  Box, Container, TextField, Button, Typography, CircularProgress,
  InputAdornment, IconButton, Divider,
} from '@mui/material';
import {
  Visibility, VisibilityOff, Shield as ShieldIcon,
  Email as EmailIcon, Lock as LockIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { login } from '@/lib/api';
import { saveAuth } from '@/lib/auth';
import GlassCard from '@/components/ui/GlassCard';
import PageTransition from '@/components/ui/PageTransition';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      toast.error('Please fill in all fields');
      return;
    }
    setLoading(true);
    try {
      const res = await login(email.trim().toLowerCase(), password);
      saveAuth(res);
      toast.success('Welcome back!');
      router.push('/dashboard');
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageTransition>
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          pt: 10,
          pb: 6,
          position: 'relative',
          zIndex: 1,
        }}
      >
        <Container maxWidth="sm">
          <motion.div
            initial={{ opacity: 0, y: 30, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          >
            <GlassCard sx={{ p: { xs: 4, md: 6 } }}>
              {/* Logo */}
              <Box sx={{ textAlign: 'center', mb: 5 }}>
                <motion.div
                  animate={{ rotate: [0, 5, -5, 0] }}
                  transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
                  style={{ display: 'inline-block' }}
                >
                  <Box
                    sx={{
                      width: 64,
                      height: 64,
                      borderRadius: 3,
                      background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      mx: 'auto',
                      mb: 3,
                      boxShadow: '0 0 40px rgba(99,102,241,0.4)',
                    }}
                  >
                    <ShieldIcon sx={{ fontSize: 32, color: '#fff' }} />
                  </Box>
                </motion.div>
                <Typography
                  variant="h4"
                  sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700, mb: 1 }}
                >
                  Welcome back
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Sign in to your KAVACH AI account
                </Typography>
              </Box>

              <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <TextField
                  label="Email address"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  fullWidth
                  slotProps={{
                    input: {
                      startAdornment: (
                        <InputAdornment position="start">
                          <EmailIcon sx={{ color: 'text.secondary', fontSize: 20 }} />
                        </InputAdornment>
                      ),
                    },
                  }}
                />

                <TextField
                  label="Password"
                  type={showPwd ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  fullWidth
                  slotProps={{
                    input: {
                      startAdornment: (
                        <InputAdornment position="start">
                          <LockIcon sx={{ color: 'text.secondary', fontSize: 20 }} />
                        </InputAdornment>
                      ),
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={() => setShowPwd(!showPwd)} size="small" edge="end">
                            {showPwd ? <VisibilityOff sx={{ fontSize: 18 }} /> : <Visibility sx={{ fontSize: 18 }} />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    },
                  }}
                />

                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Button
                    type="submit"
                    variant="contained"
                    fullWidth
                    size="large"
                    disabled={loading}
                    sx={{ py: 1.7, fontSize: '1rem', borderRadius: 2, mt: 1 }}
                  >
                    {loading ? (
                      <CircularProgress size={22} sx={{ color: 'white' }} />
                    ) : (
                      'Sign in'
                    )}
                  </Button>
                </motion.div>
              </Box>

              <Divider sx={{ my: 4, borderColor: 'rgba(99,102,241,0.15)' }}>
                <Typography variant="caption" sx={{ color: 'text.secondary', px: 1 }}>
                  NEW TO KAVACH?
                </Typography>
              </Divider>

              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  {"Don't have an account? "}
                  <Link href="/register" style={{ color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>
                    Create one free
                  </Link>
                </Typography>
              </Box>
            </GlassCard>
          </motion.div>
        </Container>
      </Box>
    </PageTransition>
  );
}
