'use client';
import { ThemeProvider, CssBaseline } from '@mui/material';
import kavachTheme from '@/components/ui/KavachTheme';
import { Toaster } from 'react-hot-toast';
import NavBar from '@/components/ui/NavBar';
import AnimatedBackground from '@/components/ui/AnimatedBackground';
import type { ReactNode } from 'react';

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider theme={kavachTheme}>
      <CssBaseline />
      <AnimatedBackground />
      <NavBar />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'rgba(15,15,26,0.95)',
            color: '#e2e8f0',
            border: '1px solid rgba(99,102,241,0.3)',
            borderRadius: 10,
            backdropFilter: 'blur(20px)',
            fontFamily: '"Inter", sans-serif',
            fontSize: '0.875rem',
          },
          success: { iconTheme: { primary: '#10b981', secondary: '#fff' } },
          error: { iconTheme: { primary: '#ef4444', secondary: '#fff' } },
        }}
      />
      {children}
    </ThemeProvider>
  );
}
