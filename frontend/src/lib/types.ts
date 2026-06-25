// TypeScript type definitions for all KAVACH AI API payloads

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ScanStatus = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export interface User {
  uid: string;
  username: string;
  token: string;
}

export interface AuthResponse {
  token: string;
  uid: string;
  username: string;
}

export interface ScanProgress {
  download?: string;
  jadx?: string;
  androguard?: string;
  gemini?: string;
  finalize?: string;
  dynamic_sandbox?: string;
}

export interface Permission {
  permission: string;
  status: string;
  description: string;
}

export interface Finding {
  title: string;
  description: string;
  severity: string;
  file?: string;
  type?: string;
  name?: string;
}

export interface BankingFraudBadge {
  id: string;
  title: string;
  summary: string;
  severity: string;
  details?: string[];
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
}

export interface InvestigationReport {
  summary?: string;
  dynamic_summary?: string;
  final_report?: string;
  executive_verdict?: string;
  runtime_findings_interpretation?: string;
  static_confirmed_at_runtime?: string[];
  runtime_only_findings?: string[];
  analysis_limitations?: string;
  permissions_analysis?: Permission[];
  suspicious_activities?: Finding[];
  code_vulnerabilities?: Finding[];
  recommendations?: string[];
}

export interface RiskDecomposition {
  static_score: number;
  dynamic_score: number;
  ai_score: number;
  fraud_score: number;
  composite_score: number;
  contributors?: Record<string, number>;
}

export interface DynamicAnalysisResult {
  status: string;
  event_count: number;
  events?: unknown[];
  normalized_events?: unknown[];
  trigger_transcript?: unknown[];
  runtime_findings?: unknown[];
  error_message?: string;
  has_video?: boolean;
  video_path?: string;
  current_screenshot?: string;
  screenshot_ts?: string;
  run_metadata?: {
    sandbox_status: string;
    event_count: number;
    duration_seconds: number;
    hook_packs?: string[];
  };
}

export interface CertificateInfo {
  is_signed?: boolean;
  verdict?: 'UNSIGNED' | 'DEBUG_KEY_SIGNED' | 'LEGIT_MATCHED_SIGNER' | 'MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE' | 'UNKNOWN_SELF_SIGNED_DEVELOPER';
  verdict_description?: string;
  subject?: string;
  issuer?: string;
  sha256?: string;
  valid_from?: string;
  valid_to?: string;
  serial_number?: string;
}

export interface YaraMatch {
  rule: string;
  namespace?: string;
  tags?: string[];
  meta?: {
    family?: string;
    description?: string;
    severity?: string;
    [key: string]: unknown;
  };
  strings?: unknown[];
}

export interface CallGraphNode {
  id: string;
  label: string;
  class: string;
  method: string;
  type: string;
  tags: string[];
  risk: 'benign' | 'malicious' | 'high-risk';
}

export interface CallGraphEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  risk: string;
}

export interface CallGraph {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

export interface EvasionReport {
  evasion_detected: boolean;
  evasion_score_boost: number;
  evidence_highlights: string[];
  categories_triggered: {
    vm: boolean;
    timing: boolean;
    root_frida: boolean;
    battery: boolean;
  };
}

export interface DangerousLine {
  line_number: number;
  threat_action: string;
  severity: string;
  source_line_content?: string;
  is_verified?: boolean;
}

export interface SuspiciousMethod {
  method_name: string;
  description: string;
  apis_used: string[];
}

export interface ClassAutopsyResult {
  class_name: string;
  is_malicious: boolean;
  attack_category: string;
  confidence: number;
  rationale: string;
  suspicious_methods: SuspiciousMethod[];
  dangerous_lines: DangerousLine[];
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  _verified_count?: number;
  _total_claimed?: number;
  plain_english_summary?: string;
  source?: string;
}

export interface CodeAutopsyReport {
  autopsy_status: 'SKIPPED' | 'RUNNING' | 'COMPLETE' | 'PARTIAL' | 'FAILED';
  total_classes_inspected: number;
  malicious_classes_found: number;
  class_results: ClassAutopsyResult[];
  top_smoking_guns: DangerousLine[];
  overall_threat_narrative: string;
  banking_attack_chain: string;
  error?: string;
}

export interface Evidence {
  permissions?: Finding[];
  exported_components?: Finding[];
  dangerous_manifest_flags?: Finding[];
  network_indicators?: Finding[];
  data_storage_issues?: Finding[];
  crypto_issues?: Finding[];
  hardcoded_secrets?: Finding[];
  suspicious_urls?: Finding[];
  reflection_dynamic_loading?: Finding[];
  obfuscation_signals?: Finding[];
  malware_rule_hits?: Finding[];
  dynamic_analysis?: DynamicAnalysisResult;
  certificate_info?: CertificateInfo;
  yara_matches?: YaraMatch[];
  callgraph?: CallGraph;
}

export interface BankingFraud {
  fraud_score: number;
  badges?: BankingFraudBadge[];
  recommended_actions?: string[];
}

export interface AnalysisResult {
  id?: string;
  uid?: string;
  filename?: string;
  package_name?: string;
  status: ScanStatus;
  risk_score?: number;
  threat_level?: ThreatLevel;
  absolute_threat_score?: number;
  created_at?: string;
  updated_at?: string;
  apk_url?: string;
  apk_hash?: string;
  progress?: ScanProgress;
  logs?: string[];
  investigation_report?: InvestigationReport;
  static_analysis?: {
    risk_score?: number;
    investigation_report?: InvestigationReport;
  };
  evidence?: Evidence;
  banking_fraud?: BankingFraud;
  risk_decomposition?: RiskDecomposition;
  attack_techniques?: AttackTechnique[];
  executive_verdict?: string;
  error_message?: string;
  code_autopsy?: CodeAutopsyReport;
  evasion_report?: EvasionReport;
  ml_classification?: {
    predicted_malware_family?: string;
    ml_confidence_score?: number;
    is_malicious?: boolean;
    status?: string;
    error?: string;
  };
}

export interface HistoryItem {
  id?: string;
  filename?: string;
  package_name?: string;
  status: ScanStatus;
  risk_score?: number;
  threat_level?: ThreatLevel;
  created_at?: string;
}

export interface ClusterNode {
  id: string;
  label: string;
  type: string;
  severity?: string;
  count?: number;
}

export interface ClusterLink {
  source: string;
  target: string;
  weight?: number;
}

export interface ClusterGraph {
  nodes: ClusterNode[];
  links: ClusterLink[];
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}
