'use client';
import {
  Box, Typography, Accordion, AccordionSummary, AccordionDetails,
  Chip, List, ListItem, ListItemText,
} from '@mui/material';
import {
  ExpandMore as ExpandIcon,
  Lock as PermIcon,
  BugReport as VulnIcon,
  Wifi as NetworkIcon,
  Storage as StorageIcon,
  Security as SecIcon,
  VpnKey as KeyIcon,
  Link as UrlIcon,
  Code as CodeIcon,
  BlurOn as ObfIcon,
  Dangerous as MalwareIcon,
  OpenInNew as ExportIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import type { Evidence, Finding } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
  INFO: '#6366f1',
  SAFE: '#14b8a6',
};

function getSeverityColor(severity?: string) {
  return SEVERITY_COLORS[(severity || 'INFO').toUpperCase()] || '#6366f1';
}

interface CategoryConfig {
  key: keyof Evidence;
  label: string;
  icon: React.ReactNode;
  color: string;
}

const CATEGORIES: CategoryConfig[] = [
  { key: 'permissions', label: 'Permissions', icon: <PermIcon />, color: '#6366f1' },
  { key: 'exported_components', label: 'Exported Components', icon: <ExportIcon />, color: '#8b5cf6' },
  { key: 'dangerous_manifest_flags', label: 'Dangerous Manifest Flags', icon: <SecIcon />, color: '#ef4444' },
  { key: 'network_indicators', label: 'Network Indicators', icon: <NetworkIcon />, color: '#14b8a6' },
  { key: 'data_storage_issues', label: 'Data Storage Issues', icon: <StorageIcon />, color: '#f59e0b' },
  { key: 'crypto_issues', label: 'Crypto Issues', icon: <KeyIcon />, color: '#f97316' },
  { key: 'hardcoded_secrets', label: 'Hardcoded Secrets', icon: <KeyIcon />, color: '#ef4444' },
  { key: 'suspicious_urls', label: 'Suspicious URLs', icon: <UrlIcon />, color: '#f97316' },
  { key: 'reflection_dynamic_loading', label: 'Reflection & Dynamic Loading', icon: <CodeIcon />, color: '#8b5cf6' },
  { key: 'obfuscation_signals', label: 'Obfuscation Signals', icon: <ObfIcon />, color: '#6366f1' },
  { key: 'malware_rule_hits', label: 'Malware Rule Hits', icon: <MalwareIcon />, color: '#ef4444' },
  { key: 'code_vulnerabilities' as keyof Evidence, label: 'Code Vulnerabilities', icon: <VulnIcon />, color: '#f97316' },
];

function FindingItem({ item }: { item: Finding }) {
  const color = getSeverityColor(item.severity);
  return (
    <ListItem
      disablePadding
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        py: 1.2,
        px: 1.5,
        borderRadius: 2,
        mb: 0.5,
        background: 'rgba(255,255,255,0.015)',
        border: '1px solid rgba(255,255,255,0.04)',
        '&:hover': { background: 'rgba(99,102,241,0.05)' },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, width: '100%' }}>
        {item.severity && (
          <Chip
            label={item.severity}
            size="small"
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.58rem',
              letterSpacing: '0.08em',
              background: `${color}18`,
              border: `1px solid ${color}40`,
              color,
              height: 20,
            }}
          />
        )}
        {item.title && (
          <Typography sx={{ fontSize: '0.8rem', fontWeight: 600, color: 'text.primary', flex: 1 }}>
            {item.title}
          </Typography>
        )}
        {item.name && !item.title && (
          <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.72rem', color: 'text.primary', flex: 1, wordBreak: 'break-all' }}>
            {item.name}
          </Typography>
        )}
      </Box>
      <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', lineHeight: 1.6 }}>
        {item.description}
      </Typography>
      {item.file && (
        <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.65rem', color: '#6366f1', mt: 0.5 }}>
          {item.file}
        </Typography>
      )}
    </ListItem>
  );
}

interface EvidenceAccordionProps {
  evidence?: Evidence;
  codeVulns?: Finding[];
  suspiciousActivities?: Finding[];
}

export default function EvidenceAccordion({ evidence, codeVulns, suspiciousActivities }: EvidenceAccordionProps) {
  const allEvidence = {
    ...evidence,
    code_vulnerabilities: codeVulns,
    suspicious_activities: suspiciousActivities,
  };

  const extCategories = [
    ...CATEGORIES,
    { key: 'suspicious_activities' as keyof typeof allEvidence, label: 'Suspicious Activities', icon: <SecIcon />, color: '#ef4444' },
  ];

  const categoriesWithData = extCategories.filter((cat) => {
    const items = allEvidence[cat.key as keyof typeof allEvidence];
    return Array.isArray(items) && items.length > 0;
  });

  if (categoriesWithData.length === 0) return null;

  return (
    <GlassCard sx={{ overflow: 'hidden' }}>
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.05)',
        }}
      >
        <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, fontSize: '1rem', mb: 0.3 }}>
          Evidence & Findings
        </Typography>
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          {categoriesWithData.length} category{categoriesWithData.length !== 1 ? 'ies' : 'y'} of findings detected
        </Typography>
      </Box>

      <Box sx={{ p: 2 }}>
        {categoriesWithData.map((cat, idx) => {
          const items = (allEvidence[cat.key as keyof typeof allEvidence] || []) as Finding[];
          return (
            <motion.div
              key={cat.key}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.04, duration: 0.3 }}
            >
              <Accordion disableGutters>
                <AccordionSummary expandIcon={<ExpandIcon sx={{ fontSize: 18, color: 'text.secondary' }} />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, py: 0.5 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: 1.5,
                        background: `${cat.color}15`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: cat.color,
                        '& .MuiSvgIcon-root': { fontSize: 17 },
                      }}
                    >
                      {cat.icon}
                    </Box>
                    <Typography sx={{ fontWeight: 600, fontSize: '0.875rem' }}>
                      {cat.label}
                    </Typography>
                    <Chip
                      label={items.length}
                      size="small"
                      sx={{
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: '0.65rem',
                        background: `${cat.color}18`,
                        color: cat.color,
                        border: 'none',
                        height: 20,
                        ml: 0.5,
                      }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 0, pb: 1.5 }}>
                  <List disablePadding>
                    {items.slice(0, 30).map((item, i) => (
                      <FindingItem key={i} item={item} />
                    ))}
                    {items.length > 30 && (
                      <Typography variant="caption" sx={{ color: 'text.secondary', pl: 1.5 }}>
                        + {items.length - 30} more findings
                      </Typography>
                    )}
                  </List>
                </AccordionDetails>
              </Accordion>
            </motion.div>
          );
        })}
      </Box>
    </GlassCard>
  );
}
