'use client';
import { useEffect, useState } from 'react';
import {
  Box, Typography, Chip, CircularProgress, Tooltip,
} from '@mui/material';
import { DataGrid, type GridColDef } from '@mui/x-data-grid';
import {
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  HourglassEmpty as PendingIcon,
  Refresh as RefreshIcon,
  Android as AndroidIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { getHistory } from '@/lib/api';
import type { HistoryItem } from '@/lib/types';
import ThreatBadge from '@/components/ui/ThreatBadge';
import GlassCard from '@/components/ui/GlassCard';

function StatusIcon({ status }: { status: string }) {
  if (status === 'COMPLETED') return <CheckIcon sx={{ color: '#10b981', fontSize: 18 }} />;
  if (status === 'FAILED') return <ErrorIcon sx={{ color: '#ef4444', fontSize: 18 }} />;
  if (status === 'PROCESSING') return <CircularProgress size={16} sx={{ color: '#6366f1' }} />;
  return <PendingIcon sx={{ color: '#64748b', fontSize: 18 }} />;
}

export default function ScanHistoryTable({ refreshTrigger = 0 }: { refreshTrigger?: number }) {
  const router = useRouter();
  const [rows, setRows] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await getHistory();
      setRows(data);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchHistory(); }, [refreshTrigger]);

  // Poll every 10s for live updates
  useEffect(() => {
    const interval = setInterval(fetchHistory, 10000);
    return () => clearInterval(interval);
  }, []);

  const columns: GridColDef[] = [
    {
      field: 'status',
      headerName: '',
      width: 44,
      sortable: false,
      renderCell: ({ row }) => (
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <StatusIcon status={row.status} />
        </Box>
      ),
    },
    {
      field: 'filename',
      headerName: 'Application',
      flex: 1,
      minWidth: 180,
      renderCell: ({ row }) => (
        <Box sx={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', py: 0.5 }}>
          <Typography sx={{ fontWeight: 600, fontSize: '0.85rem', color: 'text.primary', lineHeight: 1.3 }}>
            {row.filename || 'Unknown'}
          </Typography>
          <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', fontFamily: '"JetBrains Mono", monospace', lineHeight: 1.3 }}>
            {row.package_name || '—'}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'threat_level',
      headerName: 'Threat',
      width: 130,
      renderCell: ({ row }) =>
        row.threat_level ? <ThreatBadge level={row.threat_level} /> : (
          <Chip label={row.status} size="small" sx={{ fontSize: '0.65rem', fontFamily: '"JetBrains Mono"' }} />
        ),
    },
    {
      field: 'risk_score',
      headerName: 'Score',
      width: 90,
      renderCell: ({ row }) =>
        row.risk_score != null ? (
          <Typography
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontWeight: 700,
              fontSize: '0.9rem',
              color: row.risk_score >= 70 ? '#ef4444' : row.risk_score >= 40 ? '#f59e0b' : '#10b981',
            }}
          >
            {row.risk_score}
          </Typography>
        ) : <Typography sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>—</Typography>,
    },
    {
      field: 'created_at',
      headerName: 'Date',
      width: 160,
      renderCell: ({ row }) =>
        row.created_at ? (
          <Typography sx={{ fontSize: '0.78rem', color: 'text.secondary', fontFamily: '"JetBrains Mono", monospace' }}>
            {new Date(row.created_at).toLocaleString('en-IN', {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            })}
          </Typography>
        ) : <Typography sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>—</Typography>,
    },
  ];

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
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
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem', flex: 1 }}>
          Scan History
        </Typography>
        <Tooltip title="Refresh">
          <motion.div whileHover={{ rotate: 90 }} transition={{ duration: 0.3 }}>
            <RefreshIcon
              onClick={fetchHistory}
              sx={{ fontSize: 20, color: 'text.secondary', cursor: 'pointer', '&:hover': { color: '#6366f1' } }}
            />
          </motion.div>
        </Tooltip>
      </Box>

      {loading && rows.length === 0 ? (
        <Box sx={{ p: 6, textAlign: 'center' }}>
          <CircularProgress size={36} sx={{ color: '#6366f1' }} />
          <Typography variant="body2" sx={{ mt: 2, color: 'text.secondary' }}>
            Loading scan history…
          </Typography>
        </Box>
      ) : rows.length === 0 ? (
        <Box sx={{ p: 8, textAlign: 'center' }}>
          <AndroidIcon sx={{ fontSize: 56, color: 'rgba(99,102,241,0.2)', mb: 2 }} />
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, mb: 1, color: 'text.secondary' }}>
            No scans yet
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Upload an APK above to start your first analysis
          </Typography>
        </Box>
      ) : (
        <DataGrid
          rows={rows.map((r, i) => ({ ...r, id: (r as unknown as Record<string, unknown>).id || i }))}
          columns={columns}
          autoHeight
          disableColumnMenu
          disableRowSelectionOnClick={false}
          onRowClick={({ row }) => {
            const id = (row as unknown as Record<string, unknown>).id;
            if (id) router.push(`/analysis/${id}`);
          }}
          pageSizeOptions={[10, 25]}
          initialState={{ pagination: { paginationModel: { pageSize: 10 } } }}
          sx={{
            border: 'none',
            borderRadius: 0,
            '& .MuiDataGrid-columnHeaders': { background: 'rgba(99,102,241,0.05)', borderRadius: 0 },
            '& .MuiDataGrid-footerContainer': { borderTop: '1px solid rgba(99,102,241,0.1)', background: 'rgba(0,0,0,0.2)' },
          }}
        />
      )}
    </GlassCard>
  );
}
