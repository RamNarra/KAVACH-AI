'use client';
import React, { useState } from 'react';
import {
  Box,
  Typography,
  List,
  ListItemButton,
  ListItemText,
  Divider,
  Paper,
  Chip,
  Alert,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Code as CodeIcon,
  BugReport as BugIcon,
  ExpandMore as ExpandMoreIcon,
  Security as MitreIcon,
  WarningAmber as WarningIcon,
  CheckCircle as VerifiedIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import type { CodeAutopsyReport, ClassAutopsyResult } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface CodeAutopsyPanelProps {
  data?: CodeAutopsyReport;
}

export default function CodeAutopsyPanel({ data }: CodeAutopsyPanelProps) {
  const [selectedClassIdx, setSelectedClassIdx] = useState<number>(0);

  if (!data || data.autopsy_status === 'SKIPPED') {
    return (
      <GlassCard sx={{ p: 4, textAlign: 'center' }}>
        <CodeIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2, opacity: 0.5 }} />
        <Typography variant="h6" color="text.secondary" gutterBottom>
          AI Code Autopsy Not Triggered
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 450, mx: 'auto' }}>
          This scan did not trigger code autopsy. Autopsy fires automatically when static patterns match known malware signatures, banking badges, or dangerous API chains.
        </Typography>
      </GlassCard>
    );
  }

  if (data.autopsy_status === 'RUNNING') {
    return (
      <GlassCard sx={{ p: 6, textAlign: 'center' }}>
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
          style={{ display: 'inline-block', marginBottom: 16 }}
        >
          <CodeIcon sx={{ fontSize: 48, color: 'primary.main' }} />
        </motion.div>
        <Typography variant="h6" color="primary.main" gutterBottom>
          AI Code Autopsy is Running
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 450, mx: 'auto' }}>
          Autopsy runs in the background. The LLM is decompiling JADX classes and performing multi-pass inspections. Results will load in a few seconds...
        </Typography>
      </GlassCard>
    );
  }

  const classes = data.class_results || [];

  if (classes.length === 0) {
    return (
      <GlassCard sx={{ p: 4, textAlign: 'center' }}>
        <BugIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2, opacity: 0.5 }} />
        <Typography variant="h6" color="text.secondary" gutterBottom>
          No Malicious Classes Found
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Autopsy analyzed candidate classes but found no conclusively suspicious patterns.
        </Typography>
      </GlassCard>
    );
  }

  const activeClass = classes[selectedClassIdx];

  // Helper to color highlight lines
  const isDangerousLine = (lineNum: number) => {
    return activeClass?.dangerous_lines?.find((dl) => dl.line_number === lineNum);
  };

  return (
    <GlassCard>
      {/* Title Header */}
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.03)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 2,
        }}
      >
        <Box>
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <BugIcon sx={{ color: 'primary.main' }} /> AI Code Autopsy
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Inspected {data.total_classes_inspected} classes → Found {data.malicious_classes_found} malicious targets
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Chip
            size="small"
            label={`Autopsy Status: ${data.autopsy_status}`}
            color={data.autopsy_status === 'COMPLETE' ? 'success' : 'warning'}
            variant="outlined"
          />
        </Box>
      </Box>

      {/* Main Content Layout */}
      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, minHeight: 500 }}>
        {/* Left Sidebar Class Selection */}
        <Box
          sx={{
            width: { xs: '100%', md: 240 },
            borderRight: { xs: 'none', md: '1px solid rgba(255,255,255,0.08)' },
            borderBottom: { xs: '1px solid rgba(255,255,255,0.08)', md: 'none' },
            flexShrink: 0,
            overflowY: 'auto',
            maxHeight: { xs: 200, md: 600 },
            background: 'rgba(255,255,255,0.01)',
          }}
        >
          <List sx={{ p: 1 }}>
            {classes.map((cls, idx) => {
              const nameParts = cls.class_name.split('.');
              const shortName = nameParts[nameParts.length - 1];
              return (
                <ListItemButton
                  key={cls.class_name}
                  selected={selectedClassIdx === idx}
                  onClick={() => setSelectedClassIdx(idx)}
                  sx={{
                    borderRadius: 2,
                    mb: 0.5,
                    border: selectedClassIdx === idx ? '1px solid rgba(99,102,241,0.3)' : '1px solid transparent',
                    '&.Mui-selected': {
                      background: 'rgba(99,102,241,0.08)',
                      color: 'primary.main',
                      '&:hover': {
                        background: 'rgba(99,102,241,0.12)',
                      },
                    },
                  }}
                >
                  <Box sx={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', width: '100%' }}>
                    <Typography
                      sx={{
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        textOverflow: 'ellipsis',
                        overflow: 'hidden',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {shortName}
                    </Typography>
                    <Typography
                      sx={{
                        fontSize: '0.72rem',
                        color: cls.is_malicious ? 'error.main' : 'text.secondary',
                        textOverflow: 'ellipsis',
                        overflow: 'hidden',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {cls.attack_category}
                    </Typography>
                  </Box>
                </ListItemButton>
              );
            })}
          </List>
        </Box>

        {/* Right Content Panel */}
        <Box sx={{ flexGrow: 1, p: 3, display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 }}>
          {activeClass && (
            <AnimatePresence mode="wait">
              <motion.div
                key={activeClass.class_name}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                style={{ display: 'flex', flexDirection: 'column', gap: 24 }}
              >
                {/* Threat Banner */}
                <Box
                  sx={{
                    p: 2.5,
                    borderRadius: 3,
                    background: 'rgba(239, 68, 68, 0.05)',
                    border: '1px solid rgba(239, 68, 68, 0.15)',
                    display: 'flex',
                    flexDirection: { xs: 'column', sm: 'row' },
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    gap: 2,
                  }}
                >
                  <Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1, flexWrap: 'wrap' }}>
                      <Typography
                        variant="subtitle1"
                        sx={{
                          fontFamily: '"Space Grotesk", sans-serif',
                          fontWeight: 700,
                          fontSize: '1rem',
                        }}
                      >
                        {activeClass.class_name}
                      </Typography>
                      <Chip
                        label={activeClass.attack_category}
                        color="error"
                        size="small"
                        sx={{ fontWeight: 600, fontSize: '0.72rem' }}
                      />
                      {activeClass.mitre_technique_id && (
                        <Chip
                          icon={<MitreIcon sx={{ fontSize: '0.9rem !important' }} />}
                          label={`${activeClass.mitre_technique_id}: ${activeClass.mitre_technique_name}`}
                          color="secondary"
                          variant="outlined"
                          size="small"
                          sx={{ fontSize: '0.72rem' }}
                        />
                      )}
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {activeClass.plain_english_summary || activeClass.rationale}
                    </Typography>
                  </Box>
                  <Box sx={{ textAlign: { xs: 'left', sm: 'right' }, flexShrink: 0 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                      AI Confidence
                    </Typography>
                    <Typography variant="h5" sx={{ fontWeight: 700, color: 'error.main' }}>
                      {(activeClass.confidence * 100).toFixed(0)}%
                    </Typography>
                  </Box>
                </Box>

                {/* Suspicious Methods Accordion */}
                {activeClass.suspicious_methods && activeClass.suspicious_methods.length > 0 && (
                  <Accordion
                    disableGutters
                    elevation={0}
                    square
                    sx={{
                      background: 'rgba(255,255,255,0.01)',
                      border: '1px solid rgba(255,255,255,0.06)',
                      borderRadius: 2,
                      '&::before': { display: 'none' },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography sx={{ fontSize: '0.88rem', fontWeight: 600 }}>
                        Analyzed Suspicious Methods ({activeClass.suspicious_methods.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails sx={{ px: 2, pb: 2, pt: 0, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                      {activeClass.suspicious_methods.map((method, midx) => (
                        <Box
                          key={`${method.method_name}-${midx}`}
                          sx={{
                            p: 2,
                            borderRadius: 2,
                            background: 'rgba(255,255,255,0.02)',
                            borderLeft: '3px solid #f59e0b',
                          }}
                        >
                          <Typography
                            sx={{
                              fontFamily: '"JetBrains Mono", monospace',
                              fontSize: '0.82rem',
                              fontWeight: 700,
                              color: 'warning.main',
                              mb: 0.5,
                            }}
                          >
                            {method.method_name}
                          </Typography>
                          <Typography variant="body2" sx={{ fontSize: '0.78rem', color: 'text.secondary', mb: 1 }}>
                            {method.description}
                          </Typography>
                          {method.apis_used && method.apis_used.length > 0 && (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {method.apis_used.map((api, aix) => (
                                <Chip
                                  key={`${api}-${aix}`}
                                  label={api}
                                  size="small"
                                  variant="outlined"
                                  sx={{
                                    fontFamily: '"JetBrains Mono", monospace',
                                    fontSize: '0.65rem',
                                    height: 18,
                                    borderColor: 'rgba(255,255,255,0.12)',
                                  }}
                                />
                              ))}
                            </Box>
                          )}
                        </Box>
                      ))}
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Java/Smali Code Viewer with Line Highlights */}
                {activeClass.source ? (
                  <Box>
                    <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.7 }}>
                      <CodeIcon sx={{ fontSize: '1rem' }} /> Decompiled Class Bytecode / Source
                    </Typography>
                    <Paper
                      sx={{
                        background: 'rgba(10,10,15,0.95)',
                        border: '1px solid rgba(255,255,255,0.06)',
                        borderRadius: 3,
                        overflow: 'hidden',
                      }}
                    >
                      {/* Code Header Bar */}
                      <Box
                        sx={{
                          px: 2,
                          py: 1.2,
                          background: 'rgba(255,255,255,0.03)',
                          borderBottom: '1px solid rgba(255,255,255,0.06)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <Typography
                          sx={{
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: '0.78rem',
                            color: 'text.secondary',
                          }}
                        >
                          {activeClass.class_name.split('.').pop()}.java
                        </Typography>
                        <Chip
                          label="interactive source viewer"
                          size="small"
                          sx={{ fontSize: '0.65rem', height: 18, background: 'rgba(99,102,241,0.1)' }}
                        />
                      </Box>

                      {/* Source Container */}
                      <Box
                        sx={{
                          overflowX: 'auto',
                          maxHeight: 480,
                          overflowY: 'auto',
                          py: 2,
                        }}
                      >
                        {activeClass.source.split('\n').map((line, idx) => {
                          const lineNum = idx + 1;
                          const danger = isDangerousLine(lineNum);
                          return (
                            <Box key={lineNum} sx={{ display: 'flex', flexDirection: 'column' }}>
                              {/* Source Code Line */}
                              <Box
                                sx={{
                                  display: 'flex',
                                  alignItems: 'stretch',
                                  background: danger ? 'rgba(239, 68, 68, 0.12)' : 'transparent',
                                  borderLeft: danger ? '4px solid #ef4444' : '4px solid transparent',
                                  '&:hover': {
                                    background: danger ? 'rgba(239, 68, 68, 0.16)' : 'rgba(255,255,255,0.02)',
                                  },
                                }}
                              >
                                {/* Line Number */}
                                <Box
                                  sx={{
                                    width: 48,
                                    textAlign: 'right',
                                    pr: 2,
                                    userSelect: 'none',
                                    color: danger ? 'error.light' : 'text.disabled',
                                    fontFamily: '"JetBrains Mono", monospace',
                                    fontSize: '0.75rem',
                                    lineHeight: 1.5,
                                    borderRight: '1px solid rgba(255,255,255,0.05)',
                                    background: 'rgba(0,0,0,0.2)',
                                  }}
                                >
                                  {lineNum}
                                </Box>

                                {/* Line Content */}
                                <Box
                                  sx={{
                                    pl: 2,
                                    pr: 3,
                                    fontFamily: '"JetBrains Mono", monospace',
                                    fontSize: '0.75rem',
                                    lineHeight: 1.5,
                                    color: danger ? '#fca5a5' : '#e2e8f0',
                                    whiteSpace: 'pre',
                                  }}
                                >
                                  {line}
                                </Box>
                              </Box>

                              {/* Danger Inline Annotation */}
                              {danger && (
                                <Box
                                  sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    background: 'rgba(239, 68, 68, 0.08)',
                                    borderLeft: '4px solid #ef4444',
                                    py: 1,
                                    pl: 8,
                                    pr: 3,
                                    borderBottom: '1px solid rgba(239, 68, 68, 0.15)',
                                  }}
                                >
                                  <Alert
                                    severity={danger.severity?.toLowerCase() === 'high' ? 'error' : 'warning'}
                                    variant="outlined"
                                    icon={danger.is_verified ? <VerifiedIcon sx={{ fontSize: '1rem', color: '#10b981' }} /> : <WarningIcon sx={{ fontSize: '1rem' }} />}
                                    sx={{
                                      py: 0.2,
                                      px: 1.5,
                                      fontSize: '0.72rem',
                                      width: '100%',
                                      borderColor: 'rgba(239, 68, 68, 0.2)',
                                      background: 'rgba(0,0,0,0.1)',
                                      '& .MuiAlert-icon': { mr: 1, display: 'flex', alignItems: 'center' },
                                    }}
                                  >
                                    <strong>[{danger.severity?.toUpperCase()}] {danger.threat_action}</strong>
                                    {danger.is_verified && ' — Verification matches bytecode.'}
                                  </Alert>
                                </Box>
                              )}
                            </Box>
                          );
                        })}
                      </Box>
                    </Paper>
                  </Box>
                ) : (
                  <Paper sx={{ p: 4, textAlign: 'center', background: 'rgba(0,0,0,0.1)' }}>
                    <Typography variant="body2" color="text.secondary">
                      No decompiled Java source available for this class.
                    </Typography>
                  </Paper>
                )}
              </motion.div>
            </AnimatePresence>
          )}
        </Box>
      </Box>
    </GlassCard>
  );
}
