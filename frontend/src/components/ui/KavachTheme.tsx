'use client';
import { createTheme } from '@mui/material/styles';

const KAVACH_DARK = '#0a0a0f';
const KAVACH_SURFACE = '#0f0f1a';
const KAVACH_BORDER = 'rgba(99,102,241,0.2)';
const KAVACH_INDIGO = '#6366f1';
const KAVACH_TEAL = '#14b8a6';
const KAVACH_CRIMSON = '#ef4444';
const KAVACH_AMBER = '#f59e0b';
const KAVACH_EMERALD = '#10b981';
const KAVACH_TEXT = '#e2e8f0';
const KAVACH_MUTED = '#64748b';

const kavachTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: KAVACH_INDIGO,
      light: '#818cf8',
      dark: '#4f46e5',
    },
    secondary: {
      main: KAVACH_TEAL,
      light: '#5eead4',
      dark: '#0d9488',
    },
    error: {
      main: KAVACH_CRIMSON,
    },
    warning: {
      main: KAVACH_AMBER,
    },
    success: {
      main: KAVACH_EMERALD,
    },
    background: {
      default: KAVACH_DARK,
      paper: KAVACH_SURFACE,
    },
    text: {
      primary: KAVACH_TEXT,
      secondary: KAVACH_MUTED,
    },
    divider: KAVACH_BORDER,
  },
  typography: {
    fontFamily: '"Inter", "Space Grotesk", system-ui, sans-serif',
    h1: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    h2: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    h3: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 600,
      letterSpacing: '-0.01em',
    },
    h4: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 600,
    },
    h5: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 600,
    },
    h6: {
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 600,
    },
    subtitle1: {
      fontWeight: 500,
      letterSpacing: '0.01em',
    },
    body1: {
      lineHeight: 1.7,
    },
    body2: {
      lineHeight: 1.6,
      color: KAVACH_MUTED,
    },
    caption: {
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: '0.75rem',
      color: KAVACH_MUTED,
    },
    overline: {
      fontFamily: '"JetBrains Mono", monospace',
      letterSpacing: '0.15em',
      fontSize: '0.65rem',
      color: KAVACH_MUTED,
    },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: `
        * { box-sizing: border-box; }
        
        body {
          background: ${KAVACH_DARK};
          color: ${KAVACH_TEXT};
          font-family: 'Inter', system-ui, sans-serif;
        }
        
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); }
        ::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.4); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(99,102,241,0.7); }
        
        ::selection { background: rgba(99,102,241,0.3); }
      `,
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          letterSpacing: '0.01em',
          borderRadius: 8,
          padding: '10px 20px',
          transition: 'all 0.2s ease',
        },
        contained: {
          background: `linear-gradient(135deg, ${KAVACH_INDIGO}, #4f46e5)`,
          boxShadow: `0 0 20px rgba(99,102,241,0.3)`,
          '&:hover': {
            background: `linear-gradient(135deg, #818cf8, ${KAVACH_INDIGO})`,
            boxShadow: `0 0 30px rgba(99,102,241,0.5)`,
            transform: 'translateY(-1px)',
          },
        },
        outlined: {
          borderColor: KAVACH_BORDER,
          '&:hover': {
            borderColor: KAVACH_INDIGO,
            background: 'rgba(99,102,241,0.08)',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          background: 'rgba(15,15,26,0.8)',
          backdropFilter: 'blur(20px)',
          border: `1px solid ${KAVACH_BORDER}`,
          borderRadius: 16,
          boxShadow: '0 4px 40px rgba(0,0,0,0.4)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          background: 'rgba(15,15,26,0.8)',
          backdropFilter: 'blur(20px)',
          border: `1px solid ${KAVACH_BORDER}`,
          borderRadius: 16,
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: 8,
            background: 'rgba(255,255,255,0.03)',
            '& fieldset': {
              borderColor: KAVACH_BORDER,
            },
            '&:hover fieldset': {
              borderColor: 'rgba(99,102,241,0.5)',
            },
            '&.Mui-focused fieldset': {
              borderColor: KAVACH_INDIGO,
              boxShadow: `0 0 0 3px rgba(99,102,241,0.15)`,
            },
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: '0.7rem',
          fontWeight: 600,
          letterSpacing: '0.05em',
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          letterSpacing: '0.01em',
          minWidth: 120,
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          background: `linear-gradient(90deg, ${KAVACH_INDIGO}, ${KAVACH_TEAL})`,
          height: 3,
          borderRadius: '2px 2px 0 0',
        },
      },
    },
    // MuiDataGrid styling is applied via sx prop in ScanHistoryTable
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: 4,
          background: 'rgba(255,255,255,0.08)',
        },
        bar: {
          background: `linear-gradient(90deg, ${KAVACH_INDIGO}, ${KAVACH_TEAL})`,
          borderRadius: 4,
        },
      },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          background: 'rgba(255,255,255,0.02)',
          border: `1px solid ${KAVACH_BORDER}`,
          borderRadius: '12px !important',
          marginBottom: 8,
          '&:before': { display: 'none' },
          '&.Mui-expanded': {
            border: `1px solid rgba(99,102,241,0.4)`,
          },
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: 'rgba(10,10,15,0.95)',
          border: `1px solid ${KAVACH_BORDER}`,
          borderRadius: 8,
          fontSize: '0.8rem',
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          background: 'rgba(10,10,15,0.97)',
          backdropFilter: 'blur(40px)',
          border: `1px solid ${KAVACH_BORDER}`,
          borderRadius: 20,
        },
      },
    },
  },
});

export default kavachTheme;

// Threat level colors for components
export const THREAT_COLORS: Record<string, string> = {
  SAFE: '#10b981',
  LOW: '#14b8a6',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
};

export const THREAT_GLOW: Record<string, string> = {
  SAFE: '0 0 30px rgba(16,185,129,0.4)',
  LOW: '0 0 30px rgba(20,184,166,0.4)',
  MEDIUM: '0 0 30px rgba(245,158,11,0.4)',
  HIGH: '0 0 30px rgba(249,115,22,0.4)',
  CRITICAL: '0 0 30px rgba(239,68,68,0.5)',
};
