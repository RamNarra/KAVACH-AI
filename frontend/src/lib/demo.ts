import type { AnalysisDoc } from './types';

/** Demo result for judges when sandbox is offline. */
export const DEMO_ANALYSIS: AnalysisDoc = {
  id: 'demo-insecurebank',
  status: 'COMPLETED',
  filename: 'InsecureBankv2.apk',
  package_name: 'com.android.insecurebankv2',
  risk_score: 78,
  threat_level: 'HIGH',
  absolute_threat_score: 78,
  created_at: new Date().toISOString(),
  progress: {
    dynamic_sandbox: 'COMPLETED',
    finalize: 'COMPLETED'
  },
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
    reverse_engineering_summary:
      'Reverse engineering of the package `com.android.insecurebankv2` decompiled successfully using the JADX parallel pipeline.\n\nThe class structural analysis reveals that the application uses a custom SQLite DB connection helper with hardcoded decryption keys in the `CryptoUtility` class. Evasion tactics like `ro.build.fingerprint` check were identified in static class loading blocks.',
    static_analysis_summary:
      'Static checking detected critical security permissions and configuration issues.\n\nThe application requests `RECEIVE_SMS`, `SEND_SMS`, and `SYSTEM_ALERT_WINDOW` permissions. Static analysis identified broad broadcast receivers registered for processing incoming SMS OTP strings. The network configurations use cleartext HTTP endpoint strings targeting internal development addresses (http://10.0.2.2:8080).',
    dynamic_analysis_summary:
      'The sandbox runtime test successfully booted the application and executed our user simulation playbook.\n\nDuring dynamic run, we intercepted unencrypted HTTP login transmissions targeting `http://10.0.2.2:8080/login`. The runtime system observed active requests for overlay creation (SYSTEM_ALERT_WINDOW draw), and sensitive credential strings were copied directly onto the system clipboard.',
    final_report:
      'This sample app represents a high-risk sandbox profile matching signature patterns of mobile banking trojans.\n\nBoth static and dynamic tests confirm active SMS interception capabilities, overlay phishing vectors, and plaintext transmission of login requests. We recommend blocklisting this app version from SBI/BoI devices, advising customers against external APK sources, and implementing root/emulator detection in future app builds.',
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
  static_analysis: {
    risk_score: 65,
    threat_level: 'HIGH',
    absolute_threat_score: 65,
    banking_fraud: {
      fraud_score: 60,
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
      ],
      recommended_actions: [
        'Block app installation org-wide.',
        'Escalate to fraud desk — high-confidence trojan indicators.',
      ],
      indicator_count: 2,
    },
    risk_decomposition: {
      composite_score: 65,
      confidence: 'high',
      summary: 'Score 65/100 driven by static decompilation, permissions, and heuristics.',
      components: { static: 65, dynamic: 0, ai: 65, banking_fraud: 60 },
      weights: { static: 0.6, dynamic: 0.0, ai: 0.3, banking_fraud: 0.1 },
      weighted_contribution: { static: 39, dynamic: 0, ai: 19.5, banking_fraud: 6.0 },
      top_contributors: [
        { label: 'SMS interception capability', category: 'banking_fraud', weight: 20 },
      ],
    },
    attack_techniques: [
      { id: 'T1636.001', name: 'SMS Messages', tactic: 'Collection', sources: [{ source: 'banking_fraud', detail: 'SMS stealer' }] },
      { id: 'T1411', name: 'Input Prompt', tactic: 'Credential Access', sources: [{ source: 'banking_fraud', detail: 'Overlay' }] },
    ],
    investigation_report: {
      summary: 'Static analysis confirms SMS interception and overlay risks.',
      executive_verdict: 'Static checks match InsecureBankv2 signatures.',
      reverse_engineering_summary:
        'Static decompilation was performed successfully using a gil-free decompiler thread-pool.\n\nDEX constants analysis identified anti-VM signature checking routines in static class declarations. Obfuscation signatures check succeeded with base packers.',
      static_analysis_summary:
        'Manifest audits reveal a highly aggressive permission profile.\n\nThe app requests dangerous privileges to receive and send SMS messages, draw overlay windows, and communicate with external servers. plaintext network URLs were found inside the class constants.',
      dynamic_analysis_summary:
        'Dynamic analysis is unavailable or not yet completed for this phase. Sandbox traces require booting a live Android Virtual Device.',
      final_report:
        'Static checks identify high-confidence indicators of banking trojans.\n\nThe combination of SMS broadcast receivers and overlay drawing permissions matches families targeting payment apps. Immediate deployment block is recommended pending sandbox verification.',
      suspicious_activities: [
        { title: 'SMS interception capability', description: 'Requests SMS permissions for OTP interception.', severity: 'HIGH', evidence_source: 'confirmed' },
        { title: 'Overlay drawing capability', description: 'Requests SYSTEM_ALERT_WINDOW permission.', severity: 'HIGH', evidence_source: 'confirmed' },
      ],
      code_vulnerabilities: [
        { title: 'Weak local authentication', description: 'Client-side only auth bypass possible.', severity: 'MEDIUM', evidence_source: 'confirmed' },
      ],
      recommendations: [
        'Use certificate pinning and HTTPS-only endpoints in production builds.',
      ],
    },
  },
  evidence: {
    permissions: [
      { name: 'android.permission.RECEIVE_SMS', description: 'Allows receiving SMS', risk_score: 15 },
      { name: 'android.permission.SEND_SMS', description: 'Allows sending SMS', risk_score: 15 },
      { name: 'android.permission.SYSTEM_ALERT_WINDOW', description: 'Allows drawing overlays', risk_score: 15 },
      { name: 'android.permission.INTERNET', description: 'Allows internet access', risk_score: 5 }
    ],
    exported_components: [
      { name: 'com.android.insecurebankv2.LoginActivity', type: 'activity', risk_score: 10, description: 'Exported login activity' }
    ],
    dangerous_manifest_flags: [
      { flag: 'android:allowBackup="true"', risk_score: 5, description: 'Backup is allowed' }
    ],
    malware_rule_hits: [
      { rule: 'SMSReceiver', description: 'SMS BroadcastReceiver registered', severity: 'HIGH', confidence: 'full', risk_score: 20 },
      { rule: 'OverlayDrawing', description: 'SYSTEM_ALERT_WINDOW usage', severity: 'HIGH', confidence: 'full', risk_score: 20 },
      { rule: 'Build FINGERPRINT check', description: 'Anti-VM fingerprint verification', severity: 'MEDIUM', confidence: 'full', risk_score: 10, type: 'Anti-VM Check' }
    ],
    obfuscation_signals: [
      { type: 'Obfuscator', description: 'Standard obfuscator signature check', risk_score: 5, class: 'Obfuscated' }
    ],
    suspicious_urls: [
      { url: 'http://10.0.2.2:8080/login', file: 'LoginActivity.java', type: 'Cleartext URL', risk_score: 15 }
    ],
    network_indicators: [
      { type: 'Cleartext HTTP', risk_score: 10, description: 'Use of cleartext HTTP detected in XML config', source: 'xml' }
    ],
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
