export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AnalysisStatus = 'PROCESSING' | 'COMPLETED' | 'FAILED';

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
  investigation_report?: {
    summary?: string;
    executive_verdict?: string;
    suspicious_activities?: { title: string; description: string; severity?: string }[];
    code_vulnerabilities?: { title: string; description: string; severity?: string }[];
    recommendations?: string[];
  };
  evidence?: {
    dynamic_analysis?: {
      status?: string;
      runtime_findings?: { title?: string; summary?: string; severity?: string }[];
      run_metadata?: {
        event_count?: number;
        runtime_confidence?: string;
        sandbox_status?: string;
      };
    };
  };
}
