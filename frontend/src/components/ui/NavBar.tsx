'use client';
import { useState, useEffect } from 'react';
import {
  AppBar, Toolbar, Box, Button, IconButton, Menu, MenuItem,
  Typography, Divider, Avatar, Tooltip,
} from '@mui/material';
import {
  Shield as ShieldIcon,
  Dashboard as DashboardIcon,
  Logout as LogoutIcon,
  Settings as SettingsIcon,
  Person as PersonIcon,
} from '@mui/icons-material';
import { useRouter, usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import { isLoggedIn, getUsername, clearAuth } from '@/lib/auth';
import Link from 'next/link';

export default function NavBar() {
  const router = useRouter();
  const pathname = usePathname();
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    setLoggedIn(isLoggedIn());
    setUsername(getUsername());
  }, [pathname]);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handler);
    return () => window.removeEventListener('scroll', handler);
  }, []);

  const handleLogout = () => {
    clearAuth();
    setAnchorEl(null);
    router.push('/login');
  };

  const navLinks = [
    { label: 'Dashboard', href: '/dashboard', icon: <DashboardIcon sx={{ fontSize: 16 }} /> },
  ];

  const isActive = (href: string) => pathname.startsWith(href);

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        background: scrolled
          ? 'rgba(10,10,15,0.9)'
          : 'rgba(10,10,15,0.4)',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        borderBottom: '1px solid',
        borderColor: scrolled ? 'rgba(99,102,241,0.25)' : 'rgba(99,102,241,0.1)',
        transition: 'all 0.3s ease',
        zIndex: 1200,
      }}
    >
      <Toolbar sx={{ px: { xs: 2, md: 4 }, py: 1, minHeight: 64 }}>
        {/* Logo */}
        <Link href={loggedIn ? '/dashboard' : '/'} style={{ textDecoration: 'none' }}>
          <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Box
                sx={{
                  width: 36,
                  height: 36,
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 20px rgba(99,102,241,0.4)',
                }}
              >
                <ShieldIcon sx={{ fontSize: 20, color: '#fff' }} />
              </Box>
              <Box>
                <Typography
                  sx={{
                    fontFamily: '"Space Grotesk", sans-serif',
                    fontWeight: 700,
                    fontSize: '1.1rem',
                    color: '#e2e8f0',
                    lineHeight: 1,
                    letterSpacing: '-0.01em',
                  }}
                >
                  KAVACH AI
                </Typography>
                <Typography
                  sx={{
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: '0.6rem',
                    color: '#6366f1',
                    letterSpacing: '0.12em',
                    lineHeight: 1,
                    mt: 0.3,
                  }}
                >
                  SECURITY PLATFORM
                </Typography>
              </Box>
            </Box>
          </motion.div>
        </Link>

        <Box sx={{ flex: 1 }} />

        {/* Nav links */}
        {loggedIn && (
          <Box sx={{ display: 'flex', gap: 0.5, mr: 2 }}>
            {navLinks.map((link) => (
              <Button
                key={link.href}
                component={Link}
                href={link.href}
                startIcon={link.icon}
                size="small"
                sx={{
                  color: isActive(link.href) ? '#6366f1' : 'text.secondary',
                  fontWeight: isActive(link.href) ? 700 : 500,
                  background: isActive(link.href) ? 'rgba(99,102,241,0.12)' : 'transparent',
                  border: isActive(link.href) ? '1px solid rgba(99,102,241,0.3)' : '1px solid transparent',
                  px: 2,
                  '&:hover': {
                    background: 'rgba(99,102,241,0.1)',
                    color: '#818cf8',
                  },
                }}
              >
                {link.label}
              </Button>
            ))}
          </Box>
        )}

        {/* Auth buttons / user menu */}
        {loggedIn ? (
          <>
            <Tooltip title={username ?? 'Account'}>
              <IconButton
                onClick={(e) => setAnchorEl(e.currentTarget)}
                sx={{
                  border: '1px solid rgba(99,102,241,0.3)',
                  '&:hover': { border: '1px solid rgba(99,102,241,0.6)', background: 'rgba(99,102,241,0.1)' },
                }}
              >
                <Avatar
                  sx={{
                    width: 28,
                    height: 28,
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
                  }}
                >
                  {username?.[0]?.toUpperCase() ?? 'K'}
                </Avatar>
              </IconButton>
            </Tooltip>
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={() => setAnchorEl(null)}
              slotProps={{
                paper: {
                  sx: {
                    mt: 1.5,
                    minWidth: 200,
                    background: 'rgba(10,10,15,0.97)',
                    backdropFilter: 'blur(30px)',
                    border: '1px solid rgba(99,102,241,0.2)',
                    borderRadius: 2,
                    '& .MuiMenuItem-root': {
                      fontSize: '0.875rem',
                      gap: 1.5,
                      py: 1.2,
                      '&:hover': { background: 'rgba(99,102,241,0.1)' },
                    },
                  },
                },
              }}
            >
              <Box sx={{ px: 2, py: 1 }}>
                <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                  Signed in as
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.8rem' }}>
                  {username}
                </Typography>
              </Box>
              <Divider sx={{ borderColor: 'rgba(99,102,241,0.15)' }} />
              <MenuItem onClick={() => { setAnchorEl(null); router.push('/settings'); }}>
                <SettingsIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                Settings
              </MenuItem>
              <Divider sx={{ borderColor: 'rgba(99,102,241,0.15)' }} />
              <MenuItem onClick={handleLogout} sx={{ color: '#ef4444 !important' }}>
                <LogoutIcon sx={{ fontSize: 18, color: '#ef4444' }} />
                Sign out
              </MenuItem>
            </Menu>
          </>
        ) : (
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              component={Link}
              href="/login"
              variant="outlined"
              size="small"
              sx={{ borderColor: 'rgba(99,102,241,0.4)', color: 'text.secondary', fontSize: '0.85rem' }}
            >
              Sign in
            </Button>
            <Button
              component={Link}
              href="/register"
              variant="contained"
              size="small"
              sx={{ fontSize: '0.85rem' }}
            >
              Get Started
            </Button>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  );
}
