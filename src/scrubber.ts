// Pre-inference utility to mask secrets in diffs
export class Scrubber {
  private patterns = [
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

  scrub(input: string): string {
    let scrubbed = input;
    this.patterns.forEach((pattern) => {
      scrubbed = scrubbed.replace(pattern, (match) => {
        const prefix = match.split(/[:=]/)[0].trim();
        return `${prefix}="[REDACTED]"`;
      });
    });
    return scrubbed;
  }
}

export const scrubber = new Scrubber();
