import { z } from 'zod';

// Security finding from Guppy's analysis
export const FindingSchema = z.object({
  file: z.string().describe('File path from diff'),
  line: z.number().describe('Line number (1-indexed)'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).describe('Severity level'),
  type: z.string().describe('Vulnerability type (e.g., "SQL Injection", "XSS")'),
  message: z.string().describe('Detailed explanation of the issue'),
  fix: z.string().describe('Recommended fix or mitigation'),
});

export type Finding = z.infer<typeof FindingSchema>;

export const FindingsSchema = z.array(FindingSchema);

// Action inputs
export const ActionInputsSchema = z.object({
  api_key: z.string().describe('LLM API key'),
  provider: z.enum(['anthropic', 'openai', 'google']).default('anthropic'),
  model: z.string().default('claude-3-5-sonnet-20241022'),
  post_comments: z.boolean().default(true),
  fail_on_severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).default('high'),
  github_token: z.string().describe('GitHub token for Octokit'),
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
