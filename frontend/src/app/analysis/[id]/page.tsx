'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { Box, Container, Typography, Button, CircularProgress, Tabs, Tab } from '@mui/material';
import Grid from '@mui/material/Grid';
import { ArrowBack as BackIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import { use } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn } from '@/lib/auth';
import { getAnalysis, createAnalysisStream } from '@/lib/api';
import type { AnalysisResult } from '@/lib/types';
import PageTransition from '@/components/ui/PageTransition';
import AnalysisHero from '@/components/analysis/AnalysisHero';
import ProgressTracker from '@/components/analysis/ProgressTracker';
import InvestigationReport from '@/components/analysis/InvestigationReport';
import EvidenceAccordion from '@/components/analysis/EvidenceAccordion';
import BankingFraudPanel from '@/components/analysis/BankingFraudPanel';
import AttackTechniqueMap from '@/components/analysis/AttackTechniqueMap';
import RiskDecompositionPanel from '@/components/analysis/RiskDecomposition';
import DynamicSandboxPanel from '@/components/analysis/DynamicSandboxPanel';
import ChatAnalyst from '@/components/analysis/ChatAnalyst';
import LiveLogsConsole from '@/components/analysis/LiveLogsConsole';

// New tab panels
import CodeAutopsyPanel from '@/components/analysis/CodeAutopsyPanel';
import CallGraphPanel from '@/components/analysis/CallGraphPanel';
import CampaignsPanel from '@/components/analysis/CampaignsPanel';
import CertificatePanel from '@/components/analysis/CertificatePanel';
import YaraEvasionPanel from '@/components/analysis/YaraEvasionPanel';

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function AnalysisPage({ params }: PageProps) {
  const { id } = use(params);
  const router = useRouter();
  const [data, setData] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<number>(0);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
  }, [router]);

  const fetchData = useCallback(async () => {
    try {
      const result = await getAnalysis(id);
      setData(result);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const statusRef = useRef<string | undefined>(undefined);
  useEffect(() => {
    statusRef.current = data?.status;
  }, [data?.status]);

  // SSE streaming for live updates
  useEffect(() => {
    if (!id) return;

    const es = createAnalysisStream(id);

    es.onmessage = (e) => {
      try {
        const parsed: AnalysisResult = JSON.parse(e.data);
        setData(parsed);
        if (parsed.status === 'COMPLETED' || parsed.status === 'FAILED') {
          es.close();
        }
      } catch {
        // ignore parse errors
      }
    };

    es.onerror = () => {
      // Let standard EventSource auto-reconnect
    };

    return () => {
      es.close();
    };
  }, [id]);

  // Separate poll interval that respects statusRef to prevent unnecessary fetch
  useEffect(() => {
    if (!id) return;
    const pollInterval = setInterval(() => {
      if (statusRef.current !== 'COMPLETED' && statusRef.current !== 'FAILED') {
        fetchData();
      }
    }, 5000);

    return () => clearInterval(pollInterval);
  }, [id, fetchData]);

  if (loading) return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: 3, zIndex: 1, position: 'relative' }}>
      <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}>
        <CircularProgress size={48} sx={{ color: '#6366f1' }} />
      </motion.div>
      <Typography variant="body2" sx={{ color: 'text.secondary', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem', letterSpacing: '0.1em' }}>
        LOADING ANALYSIS…
      </Typography>
    </Box>
  );

  if (error || !data) return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: 3, zIndex: 1, position: 'relative' }}>
      <Typography variant="h5" sx={{ color: '#ef4444' }}>Analysis not found</Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>{error}</Typography>
      <Button component={Link} href="/dashboard" variant="outlined">Back to Dashboard</Button>
    </Box>
  );

  const isProcessing = data.status === 'PROCESSING';
  const report = data.investigation_report;
  const evidence = data.evidence;
  const dynamicData = evidence?.dynamic_analysis;

  return (
    <PageTransition>
      <Box sx={{ pt: 10, pb: 8, minHeight: '100vh', position: 'relative', zIndex: 1 }}>
        <Container maxWidth="xl">

          {/* Back */}
          <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.3 }}>
            <Button
              component={Link}
              href="/dashboard"
              startIcon={<BackIcon sx={{ fontSize: 18 }} />}
              size="small"
              sx={{
                mb: 3,
                color: 'text.secondary',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.75rem',
                letterSpacing: '0.06em',
                '&:hover': { color: '#6366f1' },
              }}
            >
              BACK TO DASHBOARD
            </Button>
          </motion.div>

          {/* Hero */}
          <Box sx={{ mb: 3 }}>
            <AnalysisHero data={data} id={id} onRefresh={fetchData} />
          </Box>

          <Grid container spacing={3}>

            {/* Left column */}
            <Grid size={{ xs: 12, lg: 4 }}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>

                {/* Progress tracker — always visible while processing */}
                {(isProcessing || (data.progress && Object.keys(data.progress).length > 0)) && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
                    <ProgressTracker
                      progress={data.progress}
                      status={data.status}
                    />
                  </motion.div>
                )}

                {/* Banking fraud */}
                {data.banking_fraud && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
                    <BankingFraudPanel data={data.banking_fraud} />
                  </motion.div>
                )}

                {/* Risk decomposition */}
                {data.risk_decomposition && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
                    <RiskDecompositionPanel data={data.risk_decomposition} />
                  </motion.div>
                )}

                {/* Dynamic sandbox */}
                {dynamicData && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
                    <DynamicSandboxPanel data={dynamicData} analysisId={id} />
                  </motion.div>
                )}

              </Box>
            </Grid>

            {/* Right column */}
            <Grid size={{ xs: 12, lg: 8 }}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>

                {/* Live Console Logs — visible during processing */}
                {!report && data.logs && data.logs.length > 0 && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
                    <LiveLogsConsole logs={data.logs} />
                  </motion.div>
                )}

                {/* Tabbed layout — visible once report is ready */}
                {report && (
                  <>
                    <Box sx={{ borderBottom: 1, borderColor: 'rgba(255, 255, 255, 0.08)', mb: 1 }}>
                      <Tabs
                        value={activeTab}
                        onChange={(e, val) => setActiveTab(val)}
                        variant="scrollable"
                        scrollButtons="auto"
                        sx={{
                          '& .MuiTab-root': {
                            fontFamily: '"Space Grotesk", sans-serif',
                            fontSize: '0.85rem',
                            fontWeight: 600,
                            color: 'text.secondary',
                            textTransform: 'none',
                            minWidth: 100,
                            px: 2,
                            '&.Mui-selected': {
                              color: 'primary.main',
                            },
                          },
                          '& .MuiTabs-indicator': {
                            backgroundColor: 'primary.main',
                            height: 3,
                            borderRadius: '3px 3px 0 0',
                          },
                        }}
                      >
                        <Tab label="Report & Chat" />
                        <Tab label="Code Autopsy" />
                        <Tab label="Call Graph" />
                        <Tab label="Campaigns & Threat Intel" />
                        <Tab label="Certificate" />
                        <Tab label="Yara & Evasion" />
                      </Tabs>
                    </Box>

                    {/* Tab 0: Report & Chat */}
                    {activeTab === 0 && (
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                          <InvestigationReport report={report} />
                        </motion.div>
                        {data.attack_techniques && data.attack_techniques.length > 0 && (
                          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                            <AttackTechniqueMap techniques={data.attack_techniques} />
                          </motion.div>
                        )}
                        {evidence && (
                          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                            <EvidenceAccordion
                              evidence={evidence}
                              codeVulns={report?.code_vulnerabilities}
                              suspiciousActivities={report?.suspicious_activities}
                            />
                          </motion.div>
                        )}
                        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                          <ChatAnalyst analysisId={id} />
                        </motion.div>
                      </Box>
                    )}

                    {/* Tab 1: Code Autopsy */}
                    {activeTab === 1 && (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                        <CodeAutopsyPanel data={data.code_autopsy} />
                      </motion.div>
                    )}

                    {/* Tab 2: Call Graph */}
                    {activeTab === 2 && (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                        <CallGraphPanel data={evidence?.callgraph} />
                      </motion.div>
                    )}

                    {/* Tab 3: Campaigns & Threat Intel */}
                    {activeTab === 3 && (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                        <CampaignsPanel analysisId={id} />
                      </motion.div>
                    )}

                    {/* Tab 4: Certificate */}
                    {activeTab === 4 && (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                        <CertificatePanel data={evidence?.certificate_info} />
                      </motion.div>
                    )}

                    {/* Tab 5: Yara & Evasion */}
                    {activeTab === 5 && (
                      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                        <YaraEvasionPanel
                          yaraMatches={evidence?.yara_matches}
                          evasionReport={data.evasion_report}
                        />
                      </motion.div>
                    )}
                  </>
                )}

              </Box>
            </Grid>

          </Grid>
        </Container>
      </Box>
    </PageTransition>
  );
}
