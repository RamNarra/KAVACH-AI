'use client';
import Grid from '@mui/material/Grid';
import { useState } from 'react';
import {
  Box, Container, TextField, Button, Typography, CircularProgress,
  InputAdornment, IconButton, Divider,
} from '@mui/material';
import {
  Visibility, VisibilityOff, Shield as ShieldIcon,
  Email as EmailIcon, Lock as LockIcon, Person as PersonIcon,
  Key as KeyIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { register } from '@/lib/api';
import { saveAuth } from '@/lib/auth';
import GlassCard from '@/components/ui/GlassCard';
import PageTransition from '@/components/ui/PageTransition';

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    last_name: '',
    gemini_api_key: '',
  });
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const { email, password, confirmPassword, first_name, last_name, gemini_api_key } = form;
    if (!email || !password || !first_name || !last_name) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }
    setLoading(true);
    try {
      const res = await register(
        email.trim().toLowerCase(),
        password,
        first_name.trim(),
        last_name.trim(),
        gemini_api_key.trim() || undefined
      );
      saveAuth(res);
      toast.success('Account created! Welcome to KAVACH AI.');
      router.push('/dashboard');
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Registration failed');
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
              {/* Header */}
              <Box sx={{ textAlign: 'center', mb: 5 }}>
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
                <Typography
                  variant="h4"
                  sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700, mb: 1 }}
                >
                  Create account
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Join KAVACH AI — secure your apps today
                </Typography>
              </Box>

              <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
                <Grid container spacing={2}>
                  <Grid size={6}>
                    <TextField
                      label="First name"
                      value={form.first_name}
                      onChange={set('first_name')}
                      fullWidth
                      required
                      slotProps={{
                        input: {
                          startAdornment: <InputAdornment position="start"><PersonIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
                        },
                      }}
                    />
                  </Grid>
                  <Grid size={6}>
                    <TextField
                      label="Last name"
                      value={form.last_name}
                      onChange={set('last_name')}
                      fullWidth
                      required
                    />
                  </Grid>
                </Grid>

                <TextField
                  label="Email address"
                  type="email"
                  value={form.email}
                  onChange={set('email')}
                  autoComplete="email"
                  fullWidth
                  required
                  slotProps={{
                    input: {
                      startAdornment: <InputAdornment position="start"><EmailIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
                    },
                  }}
                />

                <TextField
                  label="Password"
                  type={showPwd ? 'text' : 'password'}
                  value={form.password}
                  onChange={set('password')}
                  fullWidth
                  required
                  helperText="Minimum 8 characters"
                  slotProps={{
                    input: {
                      startAdornment: <InputAdornment position="start"><LockIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={() => setShowPwd(!showPwd)} size="small">
                            {showPwd ? <VisibilityOff sx={{ fontSize: 18 }} /> : <Visibility sx={{ fontSize: 18 }} />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    },
                  }}
                />

                <TextField
                  label="Confirm password"
                  type={showPwd ? 'text' : 'password'}
                  value={form.confirmPassword}
                  onChange={set('confirmPassword')}
                  fullWidth
                  required
                  error={form.confirmPassword !== '' && form.password !== form.confirmPassword}
                  helperText={form.confirmPassword !== '' && form.password !== form.confirmPassword ? 'Passwords do not match' : ''}
                  slotProps={{
                    input: {
                      startAdornment: <InputAdornment position="start"><LockIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
                    },
                  }}
                />

                <Divider sx={{ borderColor: 'rgba(99,102,241,0.15)', my: 0.5 }}>
                  <Typography variant="caption" sx={{ color: 'text.secondary', px: 1 }}>
                    OPTIONAL
                  </Typography>
                </Divider>

                <TextField
                  label="Gemini API Key (optional)"
                  type="password"
                  value={form.gemini_api_key}
                  onChange={set('gemini_api_key')}
                  fullWidth
                  helperText="Provide your own Google Gemini key for higher quotas"
                  slotProps={{
                    input: {
                      startAdornment: <InputAdornment position="start"><KeyIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
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
                    {loading ? <CircularProgress size={22} sx={{ color: 'white' }} /> : 'Create Account'}
                  </Button>
                </motion.div>
              </Box>

              <Box sx={{ textAlign: 'center', mt: 4 }}>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Already have an account?{' '}
                  <Link href="/login" style={{ color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>
                    Sign in
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
