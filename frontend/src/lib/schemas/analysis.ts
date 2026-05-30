import { z } from 'zod';

export const PermissionAnalysisSchema = z.object({
  permission: z.string().optional(),
  status: z.string().optional(),
  description: z.string().optional(),
}).passthrough();
export type PermissionAnalysis = z.infer<typeof PermissionAnalysisSchema>;

export const SuspiciousActivitySchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  severity: z.string().optional(),
  file: z.string().optional(),
}).passthrough();
export type SuspiciousActivity = z.infer<typeof SuspiciousActivitySchema>;

export const CodeVulnerabilitySchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  severity: z.string().optional(),
  file: z.string().optional(),
}).passthrough();
export type CodeVulnerability = z.infer<typeof CodeVulnerabilitySchema>;

export const InvestigationReportSchema = z.object({
  summary: z.string().optional(),
  executive_verdict: z.string().optional(),
  runtime_findings_interpretation: z.string().optional(),
  static_confirmed_at_runtime: z.array(z.string()).optional(),
  runtime_only_findings: z.array(z.string()).optional(),
  analysis_limitations: z.string().optional(),
  permissions_analysis: z.array(PermissionAnalysisSchema).optional(),
  suspicious_activities: z.array(SuspiciousActivitySchema).optional(),
  code_vulnerabilities: z.array(CodeVulnerabilitySchema).optional(),
  recommendations: z.array(z.string()).optional(),
}).passthrough();
export type InvestigationReport = z.infer<typeof InvestigationReportSchema>;

export const EvidenceItemSchema = z.object({
  name: z.string().optional(),
  type: z.string().optional(),
  flag: z.string().optional(),
  url: z.string().optional(),
  rule: z.string().optional(),
  confidence: z.string().optional(),
  file: z.string().optional(),
  match: z.string().optional(),
  risk_score: z.number().optional(),
  description: z.string().optional(),
}).passthrough();
export type EvidenceItem = z.infer<typeof EvidenceItemSchema>;

export const RuntimeFindingSchema = z.object({
  id: z.string().optional(),
  title: z.string().optional(),
  severity: z.string().optional(),
  category: z.string().optional(),
  summary: z.string().optional(),
  evidence_items: z.array(z.string()).optional(),
  sample_events: z.array(z.any()).optional(),
  confidence: z.number().optional(),
  source: z.string().optional(),
  static_finding_refs: z.array(z.string()).optional(),
  event_count: z.number().optional(),
}).passthrough();
export type RuntimeFinding = z.infer<typeof RuntimeFindingSchema>;

export const DynamicAnalysisSchema = z.object({
  status: z.string().optional(),
  events: z.array(z.any()).optional(),
  normalized_events: z.array(z.any()).optional(),
  trigger_transcript: z.array(z.any()).optional(),
  runtime_findings: z.array(RuntimeFindingSchema).optional(),
  run_metadata: z.object({
    sandbox_status: z.string().optional(),
    abi_compatible: z.boolean().optional(),
    trigger_steps_attempted: z.number().optional(),
    trigger_steps_succeeded: z.number().optional(),
    event_count: z.number().optional(),
    jadx_partial_output: z.boolean().optional(),
    hook_packs: z.array(z.string()).optional(),
    duration_seconds: z.number().optional(),
    runtime_confidence: z.string().optional(),
  }).passthrough().optional(),
  error: z.string().optional(),
  error_message: z.string().nullable().optional(),
  apk_abis: z.array(z.string()).nullable().optional(),
  emulator_abis: z.array(z.string()).nullable().optional(),
}).passthrough();

export const EvidenceModelSchema = z.object({
  permissions: z.array(EvidenceItemSchema).optional(),
  exported_components: z.array(EvidenceItemSchema).optional(),
  dangerous_manifest_flags: z.array(EvidenceItemSchema).optional(),
  network_indicators: z.array(EvidenceItemSchema).optional(),
  data_storage_issues: z.array(EvidenceItemSchema).optional(),
  crypto_issues: z.array(EvidenceItemSchema).optional(),
  hardcoded_secrets: z.array(EvidenceItemSchema).optional(),
  suspicious_urls: z.array(z.object({ url: z.string(), file: z.string() }).passthrough()).optional(),
  reflection_dynamic_loading: z.array(EvidenceItemSchema).optional(),
  obfuscation_signals: z.array(EvidenceItemSchema).optional(),
  malware_rule_hits: z.array(EvidenceItemSchema).optional(),
  dynamic_analysis: DynamicAnalysisSchema.optional(),
}).passthrough();
export type EvidenceModel = z.infer<typeof EvidenceModelSchema>;

export const AnalysisResultSchema = z.object({
  id: z.string(),
  apk_url: z.string().optional(),
  package_name: z.string().optional(),
  filename: z.string().optional(),
  status: z.enum(['PROCESSING', 'COMPLETED', 'FAILED']).optional(),
  risk_score: z.number().optional(),
  threat_level: z.enum(['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  evidence: EvidenceModelSchema.optional(),
  investigation_report: InvestigationReportSchema.optional(),
  error_message: z.string().optional(),
  created_at: z.any().optional(),
  progress: z.record(z.string(), z.string()).optional(),
  logs: z.array(z.string()).optional(),
}).passthrough();

export type AnalysisResult = z.infer<typeof AnalysisResultSchema>;
