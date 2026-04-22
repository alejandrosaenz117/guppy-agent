import * as core from '@actions/core';
import cweModule, { CWEEntry } from 'fetch-cwe-list';
const fetchCweList: () => Promise<CWEEntry[]> = (cweModule as any).default ?? cweModule;
function findById(list: CWEEntry[], id: string): CWEEntry | undefined {
  return list.find((c) => c.ID === id);
}
import { Enrichable, ScaFinding, REACHABILITY_CONFIDENCE_LABELS, Finding } from './types.js';
import type { LanguageModel } from 'ai';

/**
 * Escapes markdown metacharacters to prevent injection attacks
 */
function escapeMarkdown(s: string): string {
  return s.replace(/([\\`*_{}[\]()#+\-.!<>|])/g, '\\$1');
}

/**
 * Validates and sanitizes version strings — rejects malformed versions
 */
function validateAndSanitizeVersion(v: string): string | null {
  // Allowlist version format: digits.digits.digits[optional prerelease/build]
  if (!/^[\d]+\.[\d]+\.[\d]+([\w.\-+]*)?$/.test(v)) {
    return null; // Invalid version format
  }
  // Escape any remaining markdown characters
  return v.replace(/([*_`[\]()#<>|])/g, '\\$1');
}

/**
 * Validates CVE/GHSA ID format
 */
function isValidCveId(id: string): boolean {
  return /^(CVE|GHSA)-[\w-]+$/.test(id);
}

let cweListCache: CWEEntry[] | null = null;

export async function getCweList(): Promise<CWEEntry[]> {
  if (cweListCache) return cweListCache;
  cweListCache = await fetchCweList();
  return cweListCache!;
}

// For testing: allows injecting a mock CWE list (not exported from production)
function setCweListCache(list: CWEEntry[] | null): void {
  cweListCache = list;
}

export { setCweListCache as _setCweListCache };

const EXT_TO_LANG: Record<string, string> = {
  ts: 'ts', tsx: 'ts', js: 'js', jsx: 'js', mjs: 'js', cjs: 'js',
  py: 'py', go: 'go', rb: 'rb', java: 'java', kt: 'kt',
  rs: 'rs', cs: 'cs', cpp: 'cpp', c: 'c', php: 'php',
  sh: 'sh', bash: 'sh', yaml: 'yaml', yml: 'yaml', json: 'json',
};

function getLangTag(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  return EXT_TO_LANG[ext] ?? '';
}

function sanitizeSnippet(snippet: string): { snippet: string; fenceLength: number } {
  // Find the maximum contiguous backtick run and create a fence with one more backtick
  let maxBackticks = 0;
  let current = 0;
  for (const char of snippet) {
    if (char === '`') {
      current++;
      maxBackticks = Math.max(maxBackticks, current);
    } else {
      current = 0;
    }
  }
  // Return the snippet and the fence length to use (min 3)
  return { snippet, fenceLength: Math.max(3, maxBackticks + 1) };
}

// Helper function to build CWE section for enrichment
async function buildCweSection(cwe_id?: string): Promise<string> {
  const rawId = cwe_id?.replace(/^CWE-/i, '');

  let cweSection = '';
  if (rawId) {
    try {
      const list = await getCweList();
      const cwe = findById(list, rawId);
      if (cwe) {
        cweSection += `\n\n**CWE-${cwe.ID}: ${cwe.Name}**\n${cwe.Description}`;

        if (cwe.CAPEC_IDs?.length) {
          const capecLinks = cwe.CAPEC_IDs.map(
            (id) => `[CAPEC-${id}](https://capec.mitre.org/data/definitions/${id}.html)`
          ).join(', ');
          cweSection += `\n\n**CAPEC Attack Patterns:** ${capecLinks}`;
        }

        cweSection += `\n\n**References:**`;
        cweSection += `\n- [CWE-${cwe.ID} Details](https://cwe.mitre.org/data/definitions/${cwe.ID}.html)`;

        if (cwe.Known_CVEs?.length) {
          const cveLinks = cwe.Known_CVEs.map(
            (c) => `[${c.id}](https://nvd.nist.gov/vuln/detail/${c.id})`
          ).join(', ');
          cweSection += `\n- Known CVEs: ${cveLinks}`;
        }
      }
    } catch (err) {
      core.debug('[Guppy] CWE enrichment failed: ' + err);
    }
  }

  return cweSection;
}

export async function enrichFinding(
  finding: Finding | (Enrichable & { severity?: string; type?: string; message?: string; fix?: string; fix_snippet?: string; cwe_id?: string }),
  model?: LanguageModel
): Promise<string> {
  const { severity = '', type = '', message = '', fix = '', fix_snippet, cwe_id } = finding as any;

  const cweSection = await buildCweSection(cwe_id);
  const cweLabel = cwe_id?.replace(/^CWE-/i, '') ? ` · CWE-${cwe_id?.replace(/^CWE-/i, '')}` : '';

  // Sanitize message and fix to prevent markdown injection (LLM may echo attacker-controlled diff content)
  const safMessage = escapeMarkdown(message);
  const safeFix = escapeMarkdown(fix);

  let result = `🚨 **[${severity.toUpperCase()}] ${type}**${cweLabel}\n\n${safMessage}\n\n**Recommended Fix:**\n${safeFix}`;

  // Generate secure code if model is available; otherwise use fix_snippet or fallback
  let codeToShow = fix_snippet || fix;
  if (model && !fix_snippet && fix) {
    const { generateSecureCode } = await import('./codesmith.js');
    const secureCode = await generateSecureCode(model, finding as Finding, fix);
    if (secureCode) {
      codeToShow = secureCode;
    }
  }

  const lang = getLangTag((finding as any).file ?? '');
  const { snippet: safSnippet, fenceLength } = sanitizeSnippet(codeToShow);
  const fenceChar = '`'.repeat(fenceLength);
  const fence = lang ? `${fenceChar}${lang}` : fenceChar;
  result += `\n\n**Suggested Rewrite** *(AI-generated — review before applying):*\n${fence}\n${safSnippet}\n${fenceChar}`;

  result += cweSection;
  return result;
}

export function formatScaComment(finding: ScaFinding): string {
  const { package: pkg, vulnerability, reachability, confidence } = finding;
  const severityLabel = vulnerability.severity?.toUpperCase() ?? 'UNKNOWN';

  // Validate CVE ID format before use (prevent injection attacks)
  const cveId = vulnerability.id && isValidCveId(vulnerability.id)
    ? escapeMarkdown(vulnerability.id)
    : 'UNKNOWN';

  // Escape package name and version
  const escapedPkgName = escapeMarkdown(pkg.name);
  const escapedVersion = escapeMarkdown(pkg.version);
  const packageInfo = `${escapedPkgName} ${escapedVersion}`;

  // Start with header: severity, package name/version, CVE ID
  let comment = `⚠️ **[${severityLabel}] ${packageInfo} — ${cveId}**`;

  // Add CWE ID label if available
  const cweMatch = vulnerability.details?.match(/CWE-(\d+)/i);
  if (cweMatch) {
    comment += ` · CWE-${cweMatch[1]}`;
  }

  // Add message/summary (escape to prevent markdown injection)
  const summary = vulnerability.summary || vulnerability.details;
  if (summary) {
    comment += `\n\n${escapeMarkdown(summary)}`;
  }

  // Add reachability verdict if available
  if (reachability !== null && reachability !== undefined) {
    let reachabilityLine = `\n\n**Reachability:** ${reachability}`;
    if (confidence && REACHABILITY_CONFIDENCE_LABELS[confidence]) {
      const label = REACHABILITY_CONFIDENCE_LABELS[confidence];
      reachabilityLine += ` (${label} confidence)`;
    }
    comment += reachabilityLine;
  }

  // Add fix if available
  if (vulnerability.fixed_version) {
    const sanitizedFixedVersion = validateAndSanitizeVersion(vulnerability.fixed_version);
    if (sanitizedFixedVersion) {
      comment += `\n\n**Fix:** Upgrade \`${escapedPkgName}\` to version \`${sanitizedFixedVersion}\` or later`;
    } else {
      comment += `\n\n**Fix:** Update to a patched version or apply security patches`;
    }
  } else {
    comment += `\n\n**Fix:** Update to a patched version or apply security patches`;
  }

  return comment;
}
