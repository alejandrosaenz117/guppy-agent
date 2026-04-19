// Pre-inference utility to mask secrets in diffs
export class Scrubber {
    patterns = [
        // API Keys
        /(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
        /sk[-_]live[-_][a-zA-Z0-9_-]{48}/g,
        /sk[-_]test[-_][a-zA-Z0-9_-]{48}/g,
        /pk[-_]live[-_][a-zA-Z0-9_-]{24}/g,
        // GitHub tokens (40+ hex chars or ghp_* pattern)
        /ghp_[a-zA-Z0-9_]{36,255}/g,
        /\b[a-f0-9]{40}\b/g,
        // AWS keys
        /AKIA[0-9A-Z]{16}/g,
        /aws_secret_access_key\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
        // Generic patterns
        /(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
        /(?:secret|token|bearer)\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
        // OAuth tokens
        /oauth[_-]?token\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
        /refresh[_-]?token\s*[:=]\s*['\"]([^'\"]+)['\"]/gi,
    ];
    scrub(input) {
        if (!input)
            return input;
        let scrubbed = input;
        this.patterns.forEach((pattern) => {
            scrubbed = scrubbed.replace(pattern, (match) => {
                // Check if match contains a key=value structure
                const parts = match.split(/[:=]/);
                if (parts.length > 1 && parts[0].trim().length > 0) {
                    // Key-value pattern: preserve key, redact value
                    const prefix = parts[0].trim();
                    return `${prefix}="[REDACTED]"`;
                }
                // Standalone token (no key): just redact the token
                return "[REDACTED]";
            });
        });
        return scrubbed;
    }
}
export const scrubber = new Scrubber();
//# sourceMappingURL=scrubber.js.map