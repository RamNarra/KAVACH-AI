import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Kavach',
  description: 'AI-powered APK fraud analysis for banking security teams.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
