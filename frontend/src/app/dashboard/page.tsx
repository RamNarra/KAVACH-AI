'use client';
import { useEffect, useState } from 'react';
import { Box, Container, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { isLoggedIn } from '@/lib/auth';
import PageTransition from '@/components/ui/PageTransition';
import ScanLauncher from '@/components/dashboard/ScanLauncher';
import ScanHistoryTable from '@/components/dashboard/ScanHistoryTable';
import StatsSummaryCards from '@/components/dashboard/StatsSummaryCards';

export default function DashboardPage() {
  const router = useRouter();
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
    }
  }, [router]);

  return (
    <PageTransition>
      <Box sx={{ pt: 10, pb: 8, minHeight: '100vh', position: 'relative', zIndex: 1 }}>
        <Container maxWidth="xl">

          {/* Page header */}
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <Box sx={{ mb: 5 }}>
              <Typography variant="overline" sx={{ color: '#6366f1', display: 'block', mb: 1 }}>
                SECURITY COMMAND CENTRE
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
                Dashboard
              </Typography>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                Upload an APK or paste a URL to begin your security analysis.
              </Typography>
            </Box>
          </motion.div>

          {/* Stats */}
          <Box sx={{ mb: 4 }}>
            <StatsSummaryCards />
          </Box>

          {/* Main layout */}
          <Grid container spacing={3} sx={{ alignItems: 'flex-start' }}>
            {/* Scan launcher — left */}
            <Grid size={{ xs: 12, lg: 4 }}>
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1, duration: 0.5 }}
              >
                <ScanLauncher onScanStarted={() => setRefreshTrigger((t) => t + 1)} />
              </motion.div>
            </Grid>

            {/* History table — right */}
            <Grid size={{ xs: 12, lg: 8 }}>
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.15, duration: 0.5 }}
              >
                <ScanHistoryTable refreshTrigger={refreshTrigger} />
              </motion.div>
            </Grid>
          </Grid>

        </Container>
      </Box>
    </PageTransition>
  );
}
