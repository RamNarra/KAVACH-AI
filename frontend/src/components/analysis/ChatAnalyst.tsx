'use client';
import { useState, useRef, useEffect } from 'react';
import {
  Box, Typography, TextField, Button, CircularProgress,
  Avatar, IconButton, Divider,
} from '@mui/material';
import { Send as SendIcon, Psychology as AIIcon, Close as CloseIcon } from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';

import { chat } from '@/lib/api';
import { getUid } from '@/lib/auth';
import type { ChatMessage } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

// Minimal markdown renderer without external dependency — render as plain text with basic formatting
function MarkdownText({ content }: { content: string }) {
  // Simple render: bold, code, line breaks
  return (
    <Typography
      variant="body2"
      sx={{
        color: 'text.primary',
        lineHeight: 1.75,
        fontSize: '0.875rem',
        whiteSpace: 'pre-wrap',
        '& strong': { fontWeight: 700, color: '#818cf8' },
        '& code': {
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: '0.78rem',
          background: 'rgba(99,102,241,0.12)',
          px: 0.8,
          py: 0.2,
          borderRadius: 1,
        },
      }}
      dangerouslySetInnerHTML={{
        __html: content
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/`(.*?)`/g, '<code>$1</code>')
          .replace(/\n/g, '<br/>'),
      }}
    />
  );
}

interface ChatAnalystProps {
  analysisId: string;
}

const STARTER_QUESTIONS = [
  'Is my personal data safe?',
  'What are the biggest risks?',
  'Can this app steal my passwords?',
  'What should I do now?',
];

export default function ChatAnalyst({ analysisId }: ChatAnalystProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: "Hi! I'm your **KAVACH AI Analyst**. Ask me anything about this APK's security, risks, or what actions you should take. I'll explain in simple, clear language.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async (text: string) => {
    if (!text.trim() || loading) return;
    const userMsg: ChatMessage = { role: 'user', content: text.trim(), timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);
    try {
      const res = await chat(analysisId, text.trim(), getUid() ?? undefined);
      const assistantMsg: ChatMessage = { role: 'assistant', content: res.answer, timestamp: new Date() };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: unknown) {
      const errMsg: ChatMessage = {
        role: 'assistant',
        content: `Sorry, I encountered an error: ${err instanceof Error ? err.message : 'Unknown error'}. Please try again.`,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <GlassCard sx={{ display: 'flex', flexDirection: 'column', height: 520, overflow: 'hidden' }}>
      {/* Header */}
      <Box
        sx={{
          p: 2.5,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.05)',
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          flexShrink: 0,
        }}
      >
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: 2,
            background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(99,102,241,0.4)',
          }}
        >
          <AIIcon sx={{ fontSize: 18, color: '#fff' }} />
        </Box>
        <Box>
          <Typography sx={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: '"Space Grotesk", sans-serif', lineHeight: 1 }}>
            AI Security Analyst
          </Typography>
          <Typography variant="caption" sx={{ color: '#10b981', fontSize: '0.65rem' }}>● Online</Typography>
        </Box>
      </Box>

      {/* Messages */}
      <Box sx={{ flex: 1, overflow: 'auto', p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <AnimatePresence>
          {messages.map((msg, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ duration: 0.3 }}
            >
              <Box
                sx={{
                  display: 'flex',
                  gap: 1.5,
                  flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                  alignItems: 'flex-start',
                }}
              >
                <Avatar
                  sx={{
                    width: 30,
                    height: 30,
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    background: msg.role === 'user'
                      ? 'linear-gradient(135deg, #6366f1, #4f46e5)'
                      : 'linear-gradient(135deg, #14b8a6, #0d9488)',
                    flexShrink: 0,
                  }}
                >
                  {msg.role === 'user' ? 'U' : 'AI'}
                </Avatar>
                <Box
                  sx={{
                    maxWidth: '80%',
                    p: 2,
                    borderRadius: msg.role === 'user' ? '16px 4px 16px 16px' : '4px 16px 16px 16px',
                    background: msg.role === 'user'
                      ? 'rgba(99,102,241,0.2)'
                      : 'rgba(255,255,255,0.04)',
                    border: '1px solid',
                    borderColor: msg.role === 'user'
                      ? 'rgba(99,102,241,0.35)'
                      : 'rgba(255,255,255,0.06)',
                  }}
                >
                  <MarkdownText content={msg.content} />
                  <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.62rem', mt: 0.5, display: 'block', textAlign: msg.role === 'user' ? 'right' : 'left' }}>
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </Typography>
                </Box>
              </Box>
            </motion.div>
          ))}
        </AnimatePresence>
        {loading && (
          <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
            <Avatar sx={{ width: 30, height: 30, background: 'linear-gradient(135deg, #14b8a6, #0d9488)', fontSize: '0.7rem' }}>AI</Avatar>
            <Box sx={{ p: 2, borderRadius: '4px 16px 16px 16px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <motion.div animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 1.2, repeat: Infinity }}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: '"JetBrains Mono"' }}>
                  Analyzing…
                </Typography>
              </motion.div>
            </Box>
          </Box>
        )}
        <div ref={bottomRef} />
      </Box>

      {/* Starter questions */}
      {messages.length <= 1 && (
        <Box sx={{ px: 2, pb: 1, flexShrink: 0 }}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
            {STARTER_QUESTIONS.map((q) => (
              <Button
                key={q}
                size="small"
                variant="outlined"
                onClick={() => sendMessage(q)}
                sx={{
                  fontSize: '0.72rem',
                  py: 0.5,
                  px: 1.5,
                  borderColor: 'rgba(99,102,241,0.3)',
                  color: 'text.secondary',
                  '&:hover': { borderColor: '#6366f1', color: '#818cf8', background: 'rgba(99,102,241,0.08)' },
                }}
              >
                {q}
              </Button>
            ))}
          </Box>
        </Box>
      )}

      <Divider sx={{ borderColor: 'rgba(99,102,241,0.1)', flexShrink: 0 }} />

      {/* Input */}
      <Box sx={{ p: 2, display: 'flex', gap: 1.5, flexShrink: 0 }}>
        <TextField
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(input); } }}
          placeholder="Ask anything about this APK…"
          fullWidth
          size="small"
          disabled={loading}
          multiline
          maxRows={3}
          sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2.5 } }}
        />
        <Button
          onClick={() => sendMessage(input)}
          variant="contained"
          disabled={loading || !input.trim()}
          sx={{ minWidth: 48, px: 1.5, borderRadius: 2.5 }}
        >
          {loading ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <SendIcon sx={{ fontSize: 18 }} />}
        </Button>
      </Box>
    </GlassCard>
  );
}
