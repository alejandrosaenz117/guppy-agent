import { generateObject, generateText } from 'ai';
import * as core from '@actions/core';
import { FindingsSchema } from './types';
export class Guppy {
    model;
    constructor(model) {
        this.model = model;
    }
    hunterPrompt = `You are Guppy, Admiral Ackbar's security analysis system for Bob's codebase.

Your mission: Scan the provided code diff and identify EVERY potential security vulnerability:
- SQL injection, command injection, XSS, CSRF
- Hardcoded secrets, insecure algorithms, weak cryptography
- Unsafe deserialization, XXE, path traversal
- Missing input validation, race conditions
- Weak authentication/authorization, privilege escalation
- Dependency vulnerabilities (if evident from imports)

Be paranoid. Assume the worst about external input. Rate each finding:
- critical: Can lead to immediate data loss, RCE, or authentication bypass
- high: Exploitable under realistic conditions
- medium: Exploitable but requires specific setup or user action
- low: Defense-in-depth issue or minor risk

Return ONLY JSON. If no vulnerabilities found, return [].`;
    skepticPrompt = `You are Guppy's Skeptic Pass. Given the Hunter's findings, critically analyze each one:
1. Is this a real vulnerability or a false positive?
2. Is the code actually vulnerable, or is context/framework/library preventing it?
3. Does the finding require unrealistic preconditions?

Filter out false positives. Keep only findings that are demonstrably exploitable.
Rate the filtered findings. Return only the vetted results in JSON.`;
    async audit(diff) {
        // Pass 1: Hunter - Find every potential issue
        const hunterFindings = await generateObject({
            model: this.model,
            system: this.hunterPrompt,
            prompt: `<code_diff>${diff}</code_diff>`,
            schema: FindingsSchema,
        }).catch((error) => {
            core.debug('[Guppy] Hunter pass failed: ' + (error instanceof Error ? error.message : String(error)));
            return { object: [] };
        });
        if (!hunterFindings.object || hunterFindings.object.length === 0) {
            return [];
        }
        // Pass 2: Skeptic - Filter false positives
        const skepticResponse = await generateText({
            model: this.model,
            system: this.skepticPrompt,
            prompt: `Hunter findings:\n${JSON.stringify(hunterFindings.object, null, 2)}\n\nFilter and return only real vulnerabilities as JSON array.`,
        }).catch((error) => {
            core.debug('[Guppy] Skeptic pass failed: ' + (error instanceof Error ? error.message : String(error)));
            return { text: '[]' };
        });
        try {
            const vetted = JSON.parse(skepticResponse.text);
            return FindingsSchema.parse(vetted);
        }
        catch {
            return hunterFindings.object; // Fall back to Hunter findings if Skeptic fails
        }
    }
}
//# sourceMappingURL=guppy.js.map