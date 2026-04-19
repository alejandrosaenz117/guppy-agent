import { z } from 'zod';
// Security finding from Guppy's analysis
export const FindingSchema = z.object({
    file: z.string().max(500).regex(/^[^\0\n\r]+$/).describe('File path from diff'),
    line: z.number().int().positive().describe('Line number (1-indexed)'),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).describe('Severity level'),
    type: z.string().max(200).describe('Vulnerability type (e.g., "SQL Injection", "XSS")'),
    message: z.string().max(2000).describe('Detailed explanation of the issue'),
    fix: z.string().max(2000).describe('Recommended fix or mitigation'),
});
export const FindingsSchema = z.array(FindingSchema);
// Action inputs
export const ActionInputsSchema = z.object({
    api_key: z.string().describe('LLM API key'),
    provider: z.enum(['anthropic', 'openai', 'google']).default('anthropic'),
    model: z.string().max(200).default('claude-3-5-sonnet-20241022'),
    post_comments: z.boolean().default(true),
    fail_on_severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).default('high'),
    github_token: z.string().describe('GitHub token for Octokit'),
});
// Severity levels for filtering
export const SEVERITY_ORDER = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    none: 0,
};
//# sourceMappingURL=types.js.map