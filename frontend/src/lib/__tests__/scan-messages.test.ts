import { describe, expect, it } from 'vitest';
import { livelyScanHeadline, recentScanLogs, stripLogPrefix } from '../scan-messages';

describe('scan-messages', () => {
  it('prefers the latest backend log over raw step keys', () => {
    const msg = livelyScanHeadline(
      { jadx: 'RUNNING' },
      ['[JADX] Decompiling DEX bytecode into readable Java source…'],
    );
    expect(msg).toContain('Decompiling DEX');
    expect(msg).not.toBe('jadx');
  });

  it('maps running steps to human blurbs when logs are empty', () => {
    const msg = livelyScanHeadline({ apktool: 'RUNNING' }, [], 0);
    expect(msg.toLowerCase()).toContain('manifest');
  });

  it('shows parallel engines when multiple steps run', () => {
    const msg = livelyScanHeadline(
      { apktool: 'RUNNING', jadx: 'RUNNING', apkid: 'RUNNING', dynamic_sandbox: 'RUNNING' },
      [],
      0,
    );
    expect(msg.toLowerCase()).toContain('parallel');
  });

  it('strips bracket prefixes from log lines', () => {
    expect(stripLogPrefix('[APKID] Found packer signature')).toBe('Found packer signature');
    expect(recentScanLogs(['[APKTOOL] done', '[JADX] tracing APIs'])).toEqual(['done', 'tracing APIs']);
  });
});
