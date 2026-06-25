'use client';
import { useState, useCallback } from 'react';
import {
  Box, Typography, Button, TextField, Tab, Tabs,
  LinearProgress, CircularProgress, IconButton, Tooltip,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  Link as LinkIcon,
  Android as AndroidIcon,
  Close as CloseIcon,
  PlayArrow as ScanIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import toast from 'react-hot-toast';
import { scanByUpload, scanByUrl } from '@/lib/api';
import { getUid } from '@/lib/auth';
import { useRouter } from 'next/navigation';
import GlassCard from '@/components/ui/GlassCard';

export default function ScanLauncher({ onScanStarted }: { onScanStarted?: () => void }) {
  const router = useRouter();
  const [tab, setTab] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted.length === 0) return;
    const f = accepted[0];
    if (!f.name.endsWith('.apk')) {
      toast.error('Only .apk files are accepted');
      return;
    }
    setFile(f);
    toast.success(`${f.name} selected`);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/vnd.android.package-archive': ['.apk'] },
    maxFiles: 1,
    multiple: false,
  });

  const handleScan = async () => {
    const uid = getUid() || undefined;
    setLoading(true);
    try {
      let res: { id: string; status: string };
      if (tab === 0) {
        if (!file) { toast.error('Please select an APK file'); return; }
        res = await scanByUpload(file, uid);
      } else {
        if (!url.trim()) { toast.error('Please enter an APK URL'); return; }
        res = await scanByUrl(url.trim(), uid);
      }
      toast.success('Analysis started!');
      onScanStarted?.();
      router.push(`/analysis/${res.id}`);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Scan failed to start');
    } finally {
      setLoading(false);
    }
  };

  return (
    <GlassCard
      sx={{ p: 0, overflow: 'hidden' }}
      glowColor="rgba(99,102,241,0.15)"
    >
      {/* Header */}
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
        <AndroidIcon sx={{ color: '#6366f1', fontSize: 22 }} />
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem' }}>
          Launch New Scan
        </Typography>
      </Box>

      {/* Tabs */}
      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{
          px: 3,
          borderBottom: '1px solid rgba(99,102,241,0.1)',
          '& .MuiTab-root': { minWidth: 0, fontSize: '0.85rem', py: 2 },
        }}
      >
        <Tab label="Upload APK" icon={<UploadIcon sx={{ fontSize: 16 }} />} iconPosition="start" />
        <Tab label="From URL" icon={<LinkIcon sx={{ fontSize: 16 }} />} iconPosition="start" />
      </Tabs>

      <Box sx={{ p: 3 }}>
        <AnimatePresence mode="wait">
          {tab === 0 ? (
            <motion.div
              key="upload"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 10 }}
              transition={{ duration: 0.2 }}
            >
              {/* Dropzone */}
              <Box
                {...getRootProps()}
                sx={{
                  border: '2px dashed',
                  borderColor: isDragActive ? '#6366f1' : file ? '#10b981' : 'rgba(99,102,241,0.3)',
                  borderRadius: 3,
                  p: 5,
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.25s ease',
                  background: isDragActive
                    ? 'rgba(99,102,241,0.08)'
                    : file
                    ? 'rgba(16,185,129,0.05)'
                    : 'rgba(255,255,255,0.02)',
                  '&:hover': {
                    borderColor: '#6366f1',
                    background: 'rgba(99,102,241,0.05)',
                  },
                  position: 'relative',
                }}
              >
                <input {...getInputProps()} />
                <motion.div
                  animate={isDragActive ? { scale: 1.1 } : { scale: 1 }}
                  transition={{ duration: 0.2 }}
                >
                  {file ? (
                    <>
                      <AndroidIcon sx={{ fontSize: 48, color: '#10b981', mb: 2 }} />
                      <Typography variant="body1" sx={{ fontWeight: 600, mb: 0.5, color: '#10b981' }}>
                        {file.name}
                      </Typography>
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </Typography>
                    </>
                  ) : (
                    <>
                      <UploadIcon sx={{ fontSize: 48, color: isDragActive ? '#6366f1' : 'text.secondary', mb: 2 }} />
                      <Typography variant="body1" sx={{ fontWeight: 600, mb: 1 }}>
                        {isDragActive ? 'Drop it here!' : 'Drag & drop your APK file'}
                      </Typography>
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                        or click to browse — .apk files only, max 500MB
                      </Typography>
                    </>
                  )}
                </motion.div>
                {file && (
                  <Tooltip title="Remove file">
                    <IconButton
                      size="small"
                      onClick={(e) => { e.stopPropagation(); setFile(null); }}
                      sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
                    >
                      <CloseIcon sx={{ fontSize: 16 }} />
                    </IconButton>
                  </Tooltip>
                )}
              </Box>
            </motion.div>
          ) : (
            <motion.div
              key="url"
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
            >
              <TextField
                label="APK URL"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/app.apk or gs://bucket/app.apk"
                fullWidth
                multiline
                rows={3}
                helperText="Supports HTTP, HTTPS, and Google Cloud Storage (gs://) URLs"
                sx={{ mb: 1 }}
              />
            </motion.div>
          )}
        </AnimatePresence>

        {loading && <LinearProgress sx={{ mt: 2, mb: 1, borderRadius: 2 }} />}

        <motion.div whileHover={{ scale: loading ? 1 : 1.02 }} whileTap={{ scale: 0.98 }}>
          <Button
            onClick={handleScan}
            variant="contained"
            fullWidth
            size="large"
            disabled={loading || (tab === 0 ? !file : !url.trim())}
            startIcon={loading ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <ScanIcon />}
            sx={{ mt: 3, py: 1.6, fontSize: '0.95rem', borderRadius: 2 }}
          >
            {loading ? 'Initiating Analysis…' : 'Start Analysis'}
          </Button>
        </motion.div>
      </Box>
    </GlassCard>
  );
}
