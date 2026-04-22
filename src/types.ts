import { z } from 'zod';

// SCA Types
export interface Enrichable {
  enrichable?: boolean;
}

export type ReachabilityVerdict = 'reachable' | 'unreachable' | 'unknown';

export const REACHABILITY_CONFIDENCE_LABELS: Record<1 | 2 | 3, string> = {
  1: 'low',
  2: 'medium',
  3: 'high',
};

export interface DetectedPackage {
  name: string;
  version: string;
  ecosystem: string;
}

export interface OsvVulnerability extends Enrichable {
  id: string;
  summary: string;
  details: string;
  severity?: string;
  affected_versions: string[];
  cvss_score?: number;
  package_name?: string;
  installed_version?: string;
  fixed_version?: string;
  vulnerable_function?: string;
  cwe_ids?: string[];
}

export interface ScannerAdapter {
  scan(packages: DetectedPackage[]): Promise<OsvVulnerability[]>;
  enrichVulnerabilities?(vulns: OsvVulnerability[]): Promise<OsvVulnerability[]>;
}

export interface ScaFinding {
  package: DetectedPackage;
  vulnerability: OsvVulnerability;
  reachability?: ReachabilityVerdict;
  confidence?: 1 | 2 | 3;
  file?: string; // Path to lockfile where this vulnerability was detected
}

// Security finding from Guppy's analysis
export const FindingSchema = z.object({
  file: z.string().max(500).describe('File path from diff'),
  line: z.number().int().describe('Line number (1-indexed)'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).describe('Severity level'),
  type: z.string().max(200).describe('Vulnerability type (e.g., "SQL Injection", "XSS")'),
  message: z.string().max(2000).describe('Detailed explanation of the issue'),
  fix: z.string().max(2000).describe('Recommended fix or mitigation'),
  fix_snippet: z.string().max(3000).optional().describe('Rewritten version of the vulnerable code that mitigates the issue — drop-in replaceable, not pseudocode'),
  cwe_id: z.string().max(20).optional().describe('CWE ID (e.g., "79" for XSS, "89" for SQL Injection)'),
});

export type Finding = z.infer<typeof FindingSchema>;

export const FindingsSchema = z.object({
  findings: z.array(FindingSchema),
});

// Action inputs
export const ActionInputsSchema = z.object({
  api_key: z.string().describe('LLM API key'),
  provider: z.enum(['anthropic', 'openai', 'google']).default('anthropic'),
  model: z.string().max(200).default('claude-3-5-sonnet-20241022'),
  skeptic_pass: z.boolean().default(true),
  post_comments: z.boolean().default(true),
  fail_on_severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).default('high'),
  github_token: z.string().describe('GitHub token for Octokit'),
  upload_sarif: z.boolean().default(false),
  sca_enabled: z.boolean().default(true).describe('Enable SCA (Software Composition Analysis) scanning'),
  sca_scanner: z.enum(['osv']).default('osv').describe('SCA scanner to use'),
  sca_reachability: z.boolean().default(true).describe('Enable reachability analysis for vulnerabilities'),
  sca_reachability_threshold: z.enum(['critical', 'high', 'medium', 'low', 'none']).default('high').describe('Severity threshold for reachability analysis'),
  sca_reachability_confidence_threshold: z.union([z.literal(1), z.literal(2), z.literal(3)]).default(2).describe('Confidence threshold for reachability verdicts'),
});

export type ActionInputs = z.infer<typeof ActionInputsSchema>;

// Severity levels for filtering
export const SEVERITY_ORDER = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};
