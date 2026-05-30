import type { AnalysisDoc } from './types';

/** Demo result for judges when sandbox is offline. */
export const DEMO_ANALYSIS: AnalysisDoc = {
  id: 'demo-insecurebank',
  status: 'COMPLETED',
  filename: 'InsecureBankv2.apk',
  package_name: 'com.android.insecurebankv2',
  risk_score: 78,
  threat_level: 'HIGH',
  created_at: new Date().toISOString(),
  banking_fraud: {
    fraud_score: 72,
    indicator_count: 4,
    badges: [
      {
        id: 'BANK-SMS-STEALER',
        title: 'SMS interception capability',
        severity: 'HIGH',
        summary: 'Requests SMS permissions for OTP interception.',
        evidence: ['android.permission.RECEIVE_SMS'],
      },
      {
        id: 'BANK-OVERLAY',
        title: 'Overlay / screen capture risk',
        severity: 'HIGH',
        summary: 'Can draw over banking apps.',
        evidence: ['SYSTEM_ALERT_WINDOW'],
      },
      {
        id: 'BANK-CRED-EXFIL',
        title: 'Cleartext credential traffic',
        severity: 'CRITICAL',
        summary: 'HTTP login observed at runtime.',
        evidence: ['GET http://10.0.2.2:8080/login'],
      },
    ],
    recommended_actions: [
      'Block app installation org-wide.',
      'Escalate to fraud desk — high-confidence trojan indicators.',
    ],
  },
  risk_decomposition: {
    composite_score: 78,
    confidence: 'high',
    summary: 'Score 78/100 driven by elevated banking fraud indicators, runtime behavior confirmed (high confidence).',
    components: { static: 65, dynamic: 55, ai: 78, banking_fraud: 72 },
    weights: { static: 0.35, dynamic: 0.25, ai: 0.25, banking_fraud: 0.15 },
    weighted_contribution: { static: 22.8, dynamic: 13.8, ai: 19.5, banking_fraud: 10.8 },
    top_contributors: [
      { label: 'SMS interception capability', category: 'banking_fraud', weight: 20 },
      { label: 'Cleartext HTTP traffic', category: 'dynamic', weight: 15 },
    ],
  },
  attack_techniques: [
    { id: 'T1636.001', name: 'SMS Messages', tactic: 'Collection', sources: [{ source: 'banking_fraud', detail: 'SMS stealer' }] },
    { id: 'T1411', name: 'Input Prompt', tactic: 'Credential Access', sources: [{ source: 'banking_fraud', detail: 'Overlay' }] },
    { id: 'T1437', name: 'Application Layer Protocol', tactic: 'Command and Control', sources: [{ source: 'banking_fraud', detail: 'HTTP exfil' }] },
  ],
  family_signals: {
    anti_vm: [{ description: 'Anti-VM indicator: Build.FINGERPRINT check', match: 'Build.FINGERPRINT' }],
    packers_obfuscators: [],
  },
  investigation_report: {
    executive_verdict:
      'Deliberately vulnerable banking lab app with SMS interception, overlay capability, and cleartext credential transmission — consistent with InsecureBankv2 training malware.',
    summary:
      'Static and dynamic analysis confirm intentional banking vulnerabilities suitable for fraud simulation exercises.',
    suspicious_activities: [
      { title: 'Cleartext HTTP authentication', description: 'Login credentials sent over unencrypted HTTP.', severity: 'HIGH' },
    ],
    code_vulnerabilities: [
      { title: 'Weak local authentication', description: 'Client-side only auth bypass possible.', severity: 'MEDIUM' },
    ],
    recommendations: [
      'Do not distribute outside isolated lab environments.',
      'Use certificate pinning and HTTPS-only endpoints in production builds.',
    ],
  },
  evidence: {
    dynamic_analysis: {
      status: 'COMPLETED',
      runtime_findings: [
        {
          id: 'rf_cleartext',
          title: 'Cleartext HTTP observed',
          severity: 'MEDIUM',
          summary: 'Plaintext HTTP request during sandbox execution.',
        },
      ],
      normalized_events: [
        { category: 'network', action: 'http.request', evidence: 'GET http://10.0.2.2:8080/login' },
      ],
      trigger_transcript: [{ step: 'launch', action: 'Start main activity', result: 'succeeded' }],
      run_metadata: {
        sandbox_status: 'COMPLETED',
        event_count: 8,
        runtime_confidence: 'full',
        trigger_steps_attempted: 2,
        trigger_steps_succeeded: 2,
      },
    },
  },
};
