export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AnalysisStatus = 'PROCESSING' | 'COMPLETED' | 'FAILED';

export interface FraudBadge {
  id: string;
  title: string;
  severity: string;
  summary: string;
  evidence?: string[];
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  sources?: { source: string; detail: string }[];
}

export interface RiskDecomposition {
  composite_score?: number;
  confidence?: string;
  summary?: string;
  components?: Record<string, number>;
  weights?: Record<string, number>;
  weighted_contribution?: Record<string, number>;
  top_contributors?: { label: string; category: string; weight: number }[];
}

export interface AnalysisDoc {
  id: string;
  status: AnalysisStatus;
  filename?: string;
  package_name?: string;
  risk_score?: number;
  threat_level?: ThreatLevel;
  error_message?: string;
  created_at?: string;
  progress?: Record<string, string>;
  logs?: string[];
  banking_fraud?: {
    fraud_score?: number;
    badges?: FraudBadge[];
    recommended_actions?: string[];
    indicator_count?: number;
  };
  risk_decomposition?: RiskDecomposition;
  attack_techniques?: AttackTechnique[];
  family_signals?: {
    anti_vm?: { description?: string; match?: string }[];
    packers_obfuscators?: { description?: string; type?: string }[];
  };
  investigation_report?: {
    summary?: string;
    executive_verdict?: string;
    suspicious_activities?: { title: string; description: string; severity?: string }[];
    code_vulnerabilities?: { title: string; description: string; severity?: string }[];
    recommendations?: string[];
  };
  evidence?: {
    permissions?: { name?: string; description?: string; risk_score?: number }[];
    exported_components?: { name?: string; type?: string; risk_score?: number; description?: string }[];
    dangerous_manifest_flags?: { flag?: string; risk_score?: number; description?: string }[];
    network_indicators?: { type?: string; risk_score?: number; description?: string; file?: string; source?: string }[];
    data_storage_issues?: { type?: string; risk_score?: number; description?: string; file?: string }[];
    crypto_issues?: { type?: string; risk_score?: number; description?: string; file?: string }[];
    hardcoded_secrets?: { type?: string; risk_score?: number; description?: string; file?: string; severity?: string }[];
    suspicious_urls?: { url?: string; file?: string; type?: string; value?: string; risk_score?: number; severity?: string; description?: string }[];
    reflection_dynamic_loading?: { type?: string; risk_score?: number; description?: string; file?: string; severity?: string }[];
    obfuscation_signals?: { type?: string; risk_score?: number; description?: string; file?: string; match?: string; class?: string; severity?: string }[];
    malware_rule_hits?: { rule?: string; description?: string; severity?: string; confidence?: string; risk_score?: number; type?: string; match?: string }[];
    dynamic_analysis?: {
      status?: string;
      runtime_findings?: { id?: string; title?: string; summary?: string; severity?: string }[];
      normalized_events?: unknown[];
      trigger_transcript?: unknown[];
      run_metadata?: Record<string, unknown>;
    };
  };
}
