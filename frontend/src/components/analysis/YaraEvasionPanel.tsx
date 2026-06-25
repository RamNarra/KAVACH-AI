'use client';
import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Paper,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Pattern as YaraIcon,
  Shield as ShieldIcon,
  BugReport as BugIcon,
  RemoveRedEye as EvasionIcon,
  CheckCircleOutlined as HookIcon,
  DangerousOutlined as WarningIcon,
} from '@mui/icons-material';
import type { YaraMatch, EvasionReport } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface YaraEvasionPanelProps {
  yaraMatches?: YaraMatch[];
  evasionReport?: EvasionReport;
}

export default function YaraEvasionPanel({ yaraMatches = [], evasionReport }: YaraEvasionPanelProps) {
  // Group YARA rules by malware family
  const families: Record<string, YaraMatch[]> = {};
  yaraMatches.forEach((match) => {
    const family = match.meta?.family || 'General Signature';
    if (!families[family]) {
      families[family] = [];
    }
    families[family].push(match);
  });

  const getSeverityColor = (sev?: string) => {
    const s = String(sev).toUpperCase();
    if (s === 'CRITICAL' || s === 'HIGH') return 'error';
    if (s === 'MEDIUM') return 'warning';
    return 'info';
  };

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
            <YaraIcon sx={{ color: 'primary.main' }} /> YARA & Sandbox Evasion
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Malware signature classification and anti-analysis checks
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Chip
            label={`${yaraMatches.length} YARA Hits`}
            color={yaraMatches.length > 0 ? 'error' : 'success'}
            size="small"
          />
          {evasionReport?.evasion_detected && (
            <Chip
              label="Evasion Detected"
              color="warning"
              size="small"
            />
          )}
        </Box>
      </Box>

      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {/* YARA Genome Fingerprint */}
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.7 }}>
            <YaraIcon sx={{ fontSize: '1rem' }} /> Yara Genome Fingerprint
          </Typography>

          {yaraMatches.length > 0 ? (
            <Grid container spacing={2}>
              {/* Left Column: Groupings */}
              <Grid size={{ xs: 12, md: 4 }}>
                <Paper sx={{ p: 2, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 2.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
                    Signatures Grouped by Trojan Family
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {Object.entries(families).map(([family, list]) => (
                      <Box
                        key={family}
                        sx={{
                          p: 1.2,
                          borderRadius: 2,
                          background: 'rgba(255,255,255,0.02)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          borderLeft: '3px solid #8b5cf6',
                        }}
                      >
                        <Typography sx={{ fontSize: '0.78rem', fontWeight: 600 }}>{family}</Typography>
                        <Chip label={`${list.length} rules`} size="small" sx={{ fontSize: '0.65rem', height: 16 }} />
                      </Box>
                    ))}
                  </Box>
                </Paper>
              </Grid>

              {/* Right Column: Rule Lists */}
              <Grid size={{ xs: 12, md: 8 }}>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                  {yaraMatches.map((match, idx) => (
                    <Paper
                      key={`${match.rule}-${idx}`}
                      sx={{
                        p: 2,
                        background: 'rgba(255,255,255,0.01)',
                        border: '1px solid rgba(255,255,255,0.06)',
                        borderRadius: 2.5,
                      }}
                    >
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1, flexWrap: 'wrap', gap: 1 }}>
                        <Typography
                          sx={{
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: '0.82rem',
                            fontWeight: 700,
                            color: 'primary.light',
                          }}
                        >
                          {match.rule}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <Chip
                            label={match.meta?.family || 'General'}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.65rem', height: 16 }}
                          />
                          <Chip
                            label={match.meta?.severity || 'MEDIUM'}
                            color={getSeverityColor(match.meta?.severity)}
                            size="small"
                            sx={{ fontSize: '0.65rem', height: 16, fontWeight: 700 }}
                          />
                        </Box>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.78rem' }}>
                        {match.meta?.description || 'Matched binary signature rule.'}
                      </Typography>
                    </Paper>
                  ))}
                </Box>
              </Grid>
            </Grid>
          ) : (
            <Paper sx={{ p: 3, textAlign: 'center', background: 'rgba(0,0,0,0.1)' }}>
              <Typography variant="body2" color="text.secondary">
                No matching banking Trojan signatures or YARA rules triggered.
              </Typography>
            </Paper>
          )}
        </Box>

        <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />

        {/* Sandbox Evasion Telemetry */}
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.7 }}>
            <EvasionIcon sx={{ fontSize: '1rem' }} /> Sandbox Evasion Telemetry
          </Typography>

          {evasionReport ? (
            <Grid container spacing={2}>
              {/* Evasion Status */}
              <Grid size={{ xs: 12, md: 5 }}>
                <Paper
                  sx={{
                    p: 2.5,
                    background: evasionReport.evasion_detected
                      ? 'rgba(245,158,11,0.04)'
                      : 'rgba(16,185,129,0.03)',
                    border: evasionReport.evasion_detected
                      ? '1px solid rgba(245,158,11,0.15)'
                      : '1px solid rgba(16,185,129,0.1)',
                    borderRadius: 3,
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: 2,
                  }}
                >
                  <Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                      Evasion Detection Status
                    </Typography>
                    <Typography
                      variant="h6"
                      sx={{
                        fontFamily: '"Space Grotesk", sans-serif',
                        fontWeight: 700,
                        color: evasionReport.evasion_detected ? 'warning.main' : 'success.main',
                      }}
                    >
                      {evasionReport.evasion_detected ? 'EVASION BEHAVIOR DETECTED' : 'NO EVASION DETECTED'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: '0.78rem' }}>
                      {evasionReport.evasion_detected
                        ? 'The sample actively queries system parameters to verify if it is running in an emulator, debug sandbox, or instrumentation harness.'
                        : 'No runtime stalling, VM property scanning, or emulator bypasses detected.'}
                    </Typography>
                  </Box>

                  {evasionReport.evasion_detected && (
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {evasionReport.categories_triggered.vm && <Chip label="Anti-VM" size="small" color="error" />}
                      {evasionReport.categories_triggered.timing && <Chip label="Timing Delay" size="small" color="warning" />}
                      {evasionReport.categories_triggered.root_frida && <Chip label="Root/Frida Block" size="small" color="error" />}
                      {evasionReport.categories_triggered.battery && <Chip label="Battery Check" size="small" color="info" />}
                    </Box>
                  )}
                </Paper>
              </Grid>

              {/* Sandbox Evasion Highlights */}
              <Grid size={{ xs: 12, md: 7 }}>
                <Paper sx={{ p: 2.5, background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 3 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
                    Sandbox Detections & Automated Defenses
                  </Typography>

                  {evasionReport.evidence_highlights && evasionReport.evidence_highlights.length > 0 ? (
                    <List sx={{ p: 0 }}>
                      {evasionReport.evidence_highlights.map((ev, idx) => (
                        <React.Fragment key={idx}>
                          {idx > 0 && <Divider sx={{ my: 1, borderColor: 'rgba(255,255,255,0.04)' }} />}
                          <ListItem sx={{ px: 0, py: 0.5, alignItems: 'flex-start' }}>
                            <ListItemIcon sx={{ minWidth: 28, mt: 0.3 }}>
                              <WarningIcon sx={{ color: 'warning.main', fontSize: '1rem' }} />
                            </ListItemIcon>
                            <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                              <Typography
                                sx={{
                                  fontSize: '0.78rem',
                                  color: 'text.primary',
                                  fontWeight: 500,
                                }}
                              >
                                {ev}
                              </Typography>
                              <Typography
                                sx={{
                                  fontSize: '0.7rem',
                                  color: 'success.main',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 0.5,
                                  mt: 0.3,
                                }}
                              >
                                {ev.toLowerCase().includes('su') || ev.toLowerCase().includes('frida')
                                  ? 'Defense: KAVACH sandbox spoofed execution variables (MagiskHide/Frida bypass).'
                                  : ev.toLowerCase().includes('battery')
                                  ? 'Defense: Sandbox mock framework returned active AC battery status.'
                                  : ev.toLowerCase().includes('sleep') || ev.toLowerCase().includes('stall')
                                  ? 'Defense: Sandbox bypassed execution sleep timers.'
                                  : 'Defense: Sandbox spoofed build properties to resemble a physical Samsung device.'}
                              </Typography>
                            </Box>
                          </ListItem>
                        </React.Fragment>
                      ))}
                    </List>
                  ) : (
                    <Box sx={{ py: 3, textAlign: 'center' }}>
                      <ShieldIcon sx={{ fontSize: 32, color: 'success.main', mb: 1, opacity: 0.6 }} />
                      <Typography variant="caption" color="text.disabled" sx={{ display: 'block' }}>
                        No evasion attempts captured in sandbox telemetry.
                      </Typography>
                    </Box>
                  )}
                </Paper>
              </Grid>
            </Grid>
          ) : (
            <Paper sx={{ p: 3, textAlign: 'center', background: 'rgba(0,0,0,0.1)' }}>
              <Typography variant="body2" color="text.secondary">
                No sandbox evasion telemetry report compiled.
              </Typography>
            </Paper>
          )}
        </Box>
      </Box>
    </GlassCard>
  );
}
