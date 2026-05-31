const STEP_BLURBS: Record<string, string[]> = {
  upload: [
    'Queued your APK in the analysis pipeline…',
    'Registering sample and allocating workspace…',
  ],
  download: [
    'Pulling the APK from secure storage into the lab…',
    'Streaming the binary payload — verifying integrity…',
  ],
  apktool: [
    'Unpacking the APK shell — manifest, resources, native libs…',
    'Reading AndroidManifest.xml and hunting dangerous permissions…',
    'Extracting smali, assets, and signing metadata with APKTool…',
  ],
  jadx: [
    'Decompiling DEX bytecode into readable Java source…',
    'Reconstructing classes — tracing suspicious API calls…',
    'Following obfuscated control flow through decompiled code…',
  ],
  apkid: [
    'Fingerprinting packers, obfuscators, and compiler signatures…',
    'Scanning for anti-VM tricks and known malware families…',
  ],
  dynamic_sandbox: [
    'Spinning up the Android sandbox and attaching Frida hooks…',
    'Installing the APK on the emulator — watching runtime behavior…',
    'Tracing SMS, overlays, network exfil, and accessibility abuse live…',
  ],
  gemini: [
    'Correlating static + dynamic evidence with Gemini…',
    'Synthesizing an investigator-grade verdict from all signals…',
  ],
  finalize: [
    'Scoring risk, mapping ATT&CK techniques, sealing the report…',
    'Writing fraud indicators and recommendations to your dashboard…',
  ],
};

const IDLE_LINES = [
  'Initializing forensic toolchain…',
  'Warming up decompilers and signature engines…',
  'Preparing sandbox telemetry channels…',
];

export function stripLogPrefix(line: string): string {
  const match = line.match(/^\[[^\]]+\]\s*(.+)$/);
  return match ? match[1] : line;
}

export function runningStepKey(progress?: Record<string, string>): string | null {
  if (!progress) return null;
  const running = Object.entries(progress).find(([, status]) => status === 'RUNNING');
  return running ? running[0] : null;
}

export function runningStepKeys(progress?: Record<string, string>): string[] {
  if (!progress) return [];
  return Object.entries(progress)
    .filter(([, status]) => status === 'RUNNING')
    .map(([key]) => key);
}

export function stepBlurb(step: string, seed = 0): string {
  const options = STEP_BLURBS[step];
  if (!options?.length) return step.replace(/_/g, ' ');
  return options[Math.abs(seed) % options.length];
}

export function livelyScanHeadline(
  progress?: Record<string, string>,
  logs?: string[],
  tick = 0,
): string {
  if (logs?.length) {
    return stripLogPrefix(logs[logs.length - 1]);
  }
  const running = runningStepKeys(progress);
  if (running.length >= 2) {
    const labels = running.map((step) => {
      const blurb = stepBlurb(step, tick);
      return blurb.split('—')[0].split('…')[0].trim();
    });
    return `${running.length} engines running in parallel — ${labels.slice(0, 3).join(' · ')}`;
  }
  const step = running[0];
  if (step) return stepBlurb(step, tick);
  return IDLE_LINES[tick % IDLE_LINES.length];
}

export function recentScanLogs(logs?: string[], limit = 6): string[] {
  if (!logs?.length) return [];
  return logs.slice(-limit).map(stripLogPrefix);
}
