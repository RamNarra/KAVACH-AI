'use client';
import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Paper,
  Alert,
  AlertTitle,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  AssignmentTurnedIn as TrustIcon,
  NewReleases as SuspiciousIcon,
  WorkspacePremium as CertIcon,
  DateRange as CalendarIcon,
  Fingerprint as FingerprintIcon,
  Person as UserIcon,
} from '@mui/icons-material';
import type { CertificateInfo } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface CertificatePanelProps {
  data?: CertificateInfo;
}

export default function CertificatePanel({ data }: CertificatePanelProps) {
  if (!data) {
    return (
      <GlassCard sx={{ p: 4, textAlign: 'center' }}>
        <CertIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2, opacity: 0.5 }} />
        <Typography variant="body2" color="text.secondary">
          No certificate forensic data found.
        </Typography>
      </GlassCard>
    );
  }

  const getVerdictStyle = (verdict?: string) => {
    switch (verdict) {
      case 'LEGIT_MATCHED_SIGNER':
        return {
          color: 'success.main',
          bg: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.2)',
          label: 'Official Trust Signed',
          icon: <TrustIcon color="success" />,
        };
      case 'MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE':
        return {
          color: 'error.main',
          bg: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          label: 'Trojanized Signer Clone',
          icon: <SuspiciousIcon color="error" />,
        };
      case 'DEBUG_KEY_SIGNED':
        return {
          color: 'error.main',
          bg: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          label: 'Developer Debug Signed',
          icon: <SuspiciousIcon color="error" />,
        };
      case 'UNSIGNED':
        return {
          color: 'error.main',
          bg: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          label: 'Unsigned Binary',
          icon: <SuspiciousIcon color="error" />,
        };
      case 'UNKNOWN_SELF_SIGNED_DEVELOPER':
      default:
        return {
          color: 'warning.main',
          bg: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.2)',
          label: 'Unknown Self-Signed Signer',
          icon: <SuspiciousIcon color="warning" />,
        };
    }
  };

  const style = getVerdictStyle(data.verdict);

  return (
    <GlassCard>
      {/* Header */}
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.03)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Box>
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <CertIcon sx={{ color: 'primary.main' }} /> Certificate & Signing Forensics
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Cryptographic signature baseline verification
          </Typography>
        </Box>
        <Chip
          icon={style.icon}
          label={style.label}
          sx={{
            bgcolor: style.bg,
            border: style.border,
            color: style.color,
            fontWeight: 700,
            fontSize: '0.78rem',
            '& .MuiChip-icon': { ml: 0.5 }
          }}
        />
      </Box>

      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 3.5 }}>
        {/* Verdict Details Banner */}
        <Alert
          severity={
            data.verdict === 'LEGIT_MATCHED_SIGNER'
              ? 'success'
              : data.verdict === 'UNKNOWN_SELF_SIGNED_DEVELOPER'
              ? 'warning'
              : 'error'
          }
          variant="outlined"
          sx={{
            borderRadius: 3,
            bgcolor: 'rgba(0,0,0,0.1)',
            borderColor: style.color,
          }}
        >
          <AlertTitle sx={{ fontWeight: 700, fontSize: '0.9rem' }}>Verdict: {style.label}</AlertTitle>
          {data.verdict_description || 'No signature baseline description available.'}
        </Alert>

        {/* Certificate Properties Grid */}
        {data.is_signed !== false && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.7 }}>
              <CertIcon sx={{ fontSize: '1rem' }} /> Identity Parameters
            </Typography>

            <Grid container spacing={2}>
              {/* Subject */}
              <Grid size={{ xs: 12, md: 6 }}>
                <Paper sx={{ p: 2.2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', height: '100%', borderRadius: 2.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                    <UserIcon sx={{ fontSize: '0.9rem' }} /> Subject (Distinguished Name)
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                    {data.subject || 'Unknown'}
                  </Typography>
                </Paper>
              </Grid>

              {/* Issuer */}
              <Grid size={{ xs: 12, md: 6 }}>
                <Paper sx={{ p: 2.2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', height: '100%', borderRadius: 2.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                    <UserIcon sx={{ fontSize: '0.9rem' }} /> Issuer (Certificate Authority)
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                    {data.issuer || 'Unknown'}
                  </Typography>
                </Paper>
              </Grid>

              {/* Validity Dates */}
              <Grid size={{ xs: 12 }}>
                <Paper sx={{ p: 2.2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 2.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 1 }}>
                    <CalendarIcon sx={{ fontSize: '0.9rem' }} /> Signature Validity Period
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <Typography variant="caption" color="text.secondary">Valid From</Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{data.valid_from || 'N/A'}</Typography>
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <Typography variant="caption" color="text.secondary">Valid To (Expiration)</Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{data.valid_to || 'N/A'}</Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* SHA-256 Fingerprint */}
              <Grid size={{ xs: 12 }}>
                <Paper sx={{ p: 2.2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 2.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                    <FingerprintIcon sx={{ fontSize: '0.9rem' }} /> SHA-256 Signature Fingerprint
                  </Typography>
                  <Typography
                    variant="body2"
                    sx={{
                      fontFamily: '"JetBrains Mono", monospace',
                      fontSize: '0.78rem',
                      color: 'primary.light',
                      wordBreak: 'break-all',
                      fontWeight: 600,
                    }}
                  >
                    {data.sha256 || 'Unknown'}
                  </Typography>
                </Paper>
              </Grid>

              {/* Serial Number */}
              {data.serial_number && (
                <Grid size={{ xs: 12 }}>
                  <Paper sx={{ p: 2.2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 2.5 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                      Serial Number
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem' }}>
                      {data.serial_number}
                    </Typography>
                  </Paper>
                </Grid>
              )}
            </Grid>
          </Box>
        )}
      </Box>
    </GlassCard>
  );
}
