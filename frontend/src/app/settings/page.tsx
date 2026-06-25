'use client';
import { useState } from 'react';
import {
  Box, Container, Typography, TextField, Button, CircularProgress,
  InputAdornment, Divider,
} from '@mui/material';
import { Key as KeyIcon, AccountCircle as AccountIcon, Save as SaveIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import toast from 'react-hot-toast';
import { isLoggedIn, getUsername, clearAuth } from '@/lib/auth';
import { updateGeminiKey } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';
import PageTransition from '@/components/ui/PageTransition';

export default function SettingsPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [geminiKey, setGeminiKey] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setUsername(getUsername() || '');
  }, [router]);

  const handleSaveKey = async () => {
    setSaving(true);
    try {
      await updateGeminiKey(geminiKey.trim() || null);
      toast.success('Gemini API key updated!');
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveKey = async () => {
    setSaving(true);
    try {
      await updateGeminiKey(null);
      setGeminiKey('');
      toast.success('Gemini API key removed — using platform key');
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <PageTransition>
      <Box sx={{ pt: 10, pb: 8, minHeight: '100vh', position: 'relative', zIndex: 1 }}>
        <Container maxWidth="md">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
            <Typography variant="overline" sx={{ color: '#6366f1', display: 'block', mb: 1 }}>
              ACCOUNT
            </Typography>
            <Typography
              component="h1"
              sx={{
                fontFamily: '"Space Grotesk", sans-serif',
                fontSize: { xs: '2rem', md: '2.5rem' },
                fontWeight: 700,
                letterSpacing: '-0.02em',
                mb: 1,
              }}
            >
              Settings
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mb: 5 }}>
              Manage your account preferences and API keys.
            </Typography>
          </motion.div>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>

            {/* Account info */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
              <GlassCard sx={{ p: 4 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
                  <AccountIcon sx={{ color: '#6366f1', fontSize: 20 }} />
                  <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '0.95rem' }}>
                    Account Information
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <Box sx={{ p: 2, borderRadius: 2, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.15)' }}>
                    <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.5 }}>
                      Signed in as
                    </Typography>
                    <Typography sx={{ fontWeight: 600, fontSize: '0.9rem' }}>{username}</Typography>
                  </Box>
                </Box>
              </GlassCard>
            </motion.div>

            {/* Gemini API key */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
              <GlassCard sx={{ p: 4 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
                  <KeyIcon sx={{ color: '#6366f1', fontSize: 20 }} />
                  <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '0.95rem' }}>
                    Gemini API Key
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ color: 'text.secondary', mb: 3 }}>
                  Provide your own Google Gemini API key for higher quota limits and dedicated usage.
                  Leave blank to use the platform&apos;s shared key.
                </Typography>
                <TextField
                  label="Your Gemini API Key"
                  type="password"
                  value={geminiKey}
                  onChange={(e) => setGeminiKey(e.target.value)}
                  placeholder="AIza…"
                  fullWidth
                  sx={{ mb: 2 }}
                  slotProps={{
                    input: {
                      startAdornment: <InputAdornment position="start"><KeyIcon sx={{ color: 'text.secondary', fontSize: 18 }} /></InputAdornment>,
                    },
                  }}
                />
                <Box sx={{ display: 'flex', gap: 1.5 }}>
                  <Button
                    variant="contained"
                    startIcon={saving ? <CircularProgress size={16} sx={{ color: 'white' }} /> : <SaveIcon />}
                    onClick={handleSaveKey}
                    disabled={saving || !geminiKey.trim()}
                  >
                    Save Key
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={handleRemoveKey}
                    disabled={saving}
                    sx={{ borderColor: 'rgba(239,68,68,0.4)', color: '#ef4444', '&:hover': { background: 'rgba(239,68,68,0.05)', borderColor: '#ef4444' } }}
                  >
                    Remove Key
                  </Button>
                </Box>
              </GlassCard>
            </motion.div>

            {/* Danger zone */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
              <GlassCard sx={{ p: 4, border: '1px solid rgba(239,68,68,0.2)' }}>
                <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '0.95rem', color: '#ef4444', mb: 2 }}>
                  Danger Zone
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary', mb: 3 }}>
                  Signing out will end your session.
                </Typography>
                <Button
                  variant="outlined"
                  onClick={() => { clearAuth(); router.replace('/login'); }}
                  sx={{ borderColor: 'rgba(239,68,68,0.4)', color: '#ef4444', '&:hover': { background: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' } }}
                >
                  Sign Out
                </Button>
              </GlassCard>
            </motion.div>

          </Box>
        </Container>
      </Box>
    </PageTransition>
  );
}
