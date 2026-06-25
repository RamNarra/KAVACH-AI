'use client';
import Grid from '@mui/material/Grid';
import { Box, Typography, Chip, Button, Tooltip } from '@mui/material';
import {
  Android as AndroidIcon,
  Download as DownloadIcon,
  PlayArrow as DynamicIcon,
  Cancel as CancelIcon,
  OpenInNew as OpenIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import type { AnalysisResult } from '@/lib/types';
import ThreatBadge from '@/components/ui/ThreatBadge';
import RiskGauge from '@/components/ui/RiskGauge';
import GlassCard from '@/components/ui/GlassCard';
import { THREAT_COLORS, THREAT_GLOW } from '@/components/ui/KavachTheme';
import { triggerDynamic, cancelAnalysis, getReport } from '@/lib/api';
import { getUid } from '@/lib/auth';
import toast from 'react-hot-toast';
import { useState } from 'react';

interface AnalysisHeroProps {
  data: AnalysisResult;
  id: string;
  onRefresh?: () => void;
}

export default function AnalysisHero({ data, id, onRefresh }: AnalysisHeroProps) {
  const [dynamicLoading, setDynamicLoading] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);

  const level = data.threat_level || 'SAFE';
  const score = data.risk_score ?? 0;
  const color = THREAT_COLORS[level] || '#10b981';
  const glow = THREAT_GLOW[level] || '';
  const isProcessing = data.status === 'PROCESSING';
  const isCompleted = data.status === 'COMPLETED';
  const hasDynamic = !!data.evidence?.dynamic_analysis && data.evidence.dynamic_analysis.status !== 'UNAVAILABLE';

  const handleTriggerDynamic = async () => {
    setDynamicLoading(true);
    try {
      await triggerDynamic(id, getUid() ?? undefined);
      toast.success('Dynamic analysis triggered!');
      onRefresh?.();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to trigger dynamic analysis');
    } finally {
      setDynamicLoading(false);
    }
  };

  const handleCancel = async () => {
    setCancelLoading(true);
    try {
      await cancelAnalysis(id);
      toast.success('Analysis cancelled');
      onRefresh?.();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to cancel');
    } finally {
      setCancelLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    try {
      const r = await getReport(id);
      const blob = new Blob([r.content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `kavach_report_${id.slice(0, 8)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // Try PDF endpoint
      const token = typeof window !== 'undefined' ? localStorage.getItem('kavach_token') : '';
      window.open(`/api/scans/${id}/report?token=${token}`, '_blank');
    }
  };

  return (
    <GlassCard
      sx={{
        p: { xs: 3, md: 5 },
        background: `linear-gradient(135deg, rgba(15,15,26,0.9) 0%, ${color}08 100%)`,
        border: `1px solid ${color}30`,
        boxShadow: glow,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Ambient glow */}
      <Box
        sx={{
          position: 'absolute',
          top: -60,
          right: -60,
          width: 240,
          height: 240,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${color}12 0%, transparent 70%)`,
          pointerEvents: 'none',
        }}
      />

      <Grid container spacing={4} sx={{ alignItems: 'center' }}>
        {/* App info */}
        <Grid size={{ xs: 12, md: 7 }}>
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 56,
                  height: 56,
                  borderRadius: 3,
                  background: 'rgba(99,102,241,0.15)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <AndroidIcon sx={{ fontSize: 28, color: '#6366f1' }} />
              </Box>
              <Box>
                <Typography
                  variant="h4"
                  sx={{
                    fontFamily: '"Space Grotesk", sans-serif',
                    fontWeight: 700,
                    fontSize: { xs: '1.4rem', md: '1.8rem' },
                    lineHeight: 1.2,
                    mb: 0.5,
                    wordBreak: 'break-all',
                  }}
                >
                  {data.filename || 'Unknown APK'}
                </Typography>
                <Typography
                  sx={{
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: '0.78rem',
                    color: 'text.secondary',
                    letterSpacing: '0.03em',
                  }}
                >
                  {data.package_name || 'Package unknown'}
                </Typography>
              </Box>
            </Box>

            {/* Badges */}
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.2, mb: 2, alignItems: 'center' }}>
              <ThreatBadge level={level} size="medium" />
              <Chip
                label={data.status}
                size="small"
                sx={{
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: '0.65rem',
                  letterSpacing: '0.1em',
                  background: isProcessing ? 'rgba(99,102,241,0.15)' : isCompleted ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)',
                  border: `1px solid ${isProcessing ? 'rgba(99,102,241,0.4)' : isCompleted ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'}`,
                  color: isProcessing ? '#818cf8' : isCompleted ? '#10b981' : '#ef4444',
                }}
              />
              {data.apk_hash && (
                <Tooltip title={data.apk_hash}>
                  <Chip
                    label={`SHA256: ${data.apk_hash.slice(0, 12)}…`}
                    size="small"
                    sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', background: 'rgba(255,255,255,0.04)' }}
                  />
                </Tooltip>
              )}

              {/* ML Verdict */}
              {data.ml_classification && data.ml_classification.predicted_malware_family && (
                <Chip
                  label={`ML: ${data.ml_classification.predicted_malware_family} (${(data.ml_classification.ml_confidence_score ? data.ml_classification.ml_confidence_score * 100 : 0).toFixed(0)}%)`}
                  color={data.ml_classification.is_malicious ? 'error' : 'success'}
                  variant="outlined"
                  size="small"
                  sx={{ fontSize: '0.68rem', fontWeight: 600 }}
                />
              )}

              {/* YARA Badge */}
              {data.evidence?.yara_matches && data.evidence.yara_matches.length > 0 && (
                <Chip
                  label={`YARA: ${data.evidence.yara_matches[0].meta?.family || 'Banking Trojan'}`}
                  color="error"
                  size="small"
                  sx={{ fontSize: '0.68rem', fontWeight: 700 }}
                />
              )}

              {/* Certificate Verdict */}
              {data.evidence?.certificate_info?.verdict && (
                <Chip
                  label={`CERT: ${
                    data.evidence.certificate_info.verdict === 'LEGIT_MATCHED_SIGNER' ? 'TRUSTED BANK' :
                    data.evidence.certificate_info.verdict === 'MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE' ? 'CLONE CLASH' :
                    data.evidence.certificate_info.verdict === 'DEBUG_KEY_SIGNED' ? 'DEBUG CERT' : 'UNTRUSTED'
                  }`}
                  color={data.evidence.certificate_info.verdict === 'LEGIT_MATCHED_SIGNER' ? 'success' : 'error'}
                  variant="outlined"
                  size="small"
                  sx={{ fontSize: '0.68rem', fontWeight: 600 }}
                />
              )}
            </Box>

            {/* One-line dynamic Sandbox Summary */}
            {data.investigation_report?.runtime_findings_interpretation && (
              <Box sx={{ mb: 3.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: '#14b8a6' }} />
                <Typography
                  variant="body2"
                  sx={{
                    color: 'text.secondary',
                    fontSize: '0.78rem',
                    fontFamily: '"Space Grotesk", sans-serif',
                    fontStyle: 'italic',
                  }}
                >
                  Sandbox telemetry: &quot;{data.investigation_report.runtime_findings_interpretation}&quot;
                </Typography>
              </Box>
            )}

            {/* Verdict */}
            {data.investigation_report?.executive_verdict && (
              <Box
                sx={{
                  p: 2.5,
                  borderRadius: 2,
                  background: `${color}10`,
                  border: `1px solid ${color}25`,
                  mb: 4,
                }}
              >
                <Typography variant="overline" sx={{ color, mb: 0.5, display: 'block', fontSize: '0.65rem' }}>
                  EXECUTIVE VERDICT
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.primary', lineHeight: 1.7, fontWeight: 500 }}>
                  {data.investigation_report.executive_verdict}
                </Typography>
              </Box>
            )}

            {/* Action buttons */}
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5 }}>
              {isCompleted && !hasDynamic && (
                <Button
                  variant="contained"
                  startIcon={<DynamicIcon />}
                  onClick={handleTriggerDynamic}
                  disabled={dynamicLoading}
                  sx={{
                    background: 'linear-gradient(135deg, #14b8a6, #0d9488)',
                    boxShadow: '0 0 20px rgba(20,184,166,0.3)',
                    '&:hover': { boxShadow: '0 0 30px rgba(20,184,166,0.5)' },
                  }}
                >
                  Run Dynamic Sandbox
                </Button>
              )}
              {isCompleted && (
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownloadReport}
                  sx={{ borderColor: 'rgba(99,102,241,0.4)', color: 'text.secondary' }}
                >
                  Export Report
                </Button>
              )}
              {isProcessing && (
                <Button
                  variant="outlined"
                  startIcon={<CancelIcon />}
                  onClick={handleCancel}
                  disabled={cancelLoading}
                  sx={{ borderColor: 'rgba(239,68,68,0.4)', color: '#ef4444', '&:hover': { background: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' } }}
                >
                  Cancel
                </Button>
              )}
              {data.apk_url && (
                <Tooltip title="View APK source">
                  <Button
                    variant="outlined"
                    startIcon={<OpenIcon />}
                    size="small"
                    href={data.apk_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ borderColor: 'rgba(99,102,241,0.3)', color: 'text.secondary', fontSize: '0.8rem' }}
                  >
                    Source
                  </Button>
                </Tooltip>
              )}
            </Box>
          </motion.div>
        </Grid>

        {/* Risk gauge */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
            <RiskGauge score={score} threatLevel={level} size={220} />
            <Box sx={{ textAlign: 'center' }}>
              <Typography
                sx={{
                  fontFamily: '"Space Grotesk", sans-serif',
                  fontWeight: 700,
                  fontSize: '1.2rem',
                  color,
                  textShadow: `0 0 20px ${color}`,
                }}
              >
                {level} RISK
              </Typography>
              {data.absolute_threat_score != null && data.absolute_threat_score !== score && (
                <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                  Absolute threat: {data.absolute_threat_score}/100
                </Typography>
              )}
              {data.banking_fraud?.fraud_score != null && (
                <Typography variant="caption" sx={{ color: '#f59e0b', display: 'block', mt: 0.5 }}>
                  Banking fraud: {data.banking_fraud.fraud_score}/100
                </Typography>
              )}
            </Box>
          </Box>
        </Grid>
      </Grid>
    </GlassCard>
  );
}
