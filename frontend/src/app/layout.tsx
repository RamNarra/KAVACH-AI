import type { Metadata } from 'next';
import Providers from './providers';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: 'KAVACH AI — Mobile Security Analysis Platform',
  description:
    'KAVACH AI is a state-of-the-art Android APK security analysis platform powered by Gemini AI. Detect malware, banking fraud, and security vulnerabilities in seconds.',
  keywords: ['APK analysis', 'Android security', 'malware detection', 'banking fraud', 'MITRE ATT&CK'],
  openGraph: {
    title: 'KAVACH AI — Mobile Security Analysis Platform',
    description: 'AI-powered Android APK malware and banking fraud detection.',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#0a0a0f" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#0a0a0f' }}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
