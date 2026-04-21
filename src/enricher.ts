import * as core from '@actions/core';
import cweModule, { CWEEntry } from 'fetch-cwe-list';
const fetchCweList: () => Promise<CWEEntry[]> = (cweModule as any).default ?? cweModule;
function findById(list: CWEEntry[], id: string): CWEEntry | undefined {
  return list.find((c) => c.ID === id);
}
import { Enrichable, ScaFinding, REACHABILITY_CONFIDENCE_LABELS, Finding } from './types.js';

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

export async function enrichFinding(finding: Finding | (Enrichable & { severity?: string; type?: string; message?: string; fix?: string; cwe_id?: string })): Promise<string> {
  const { severity = '', type = '', message = '', fix = '', cwe_id } = finding as any;

  const cweSection = await buildCweSection(cwe_id);
  const cweLabel = cwe_id?.replace(/^CWE-/i, '') ? ` · CWE-${cwe_id?.replace(/^CWE-/i, '')}` : '';
  return `🚨 **[${severity.toUpperCase()}] ${type}**${cweLabel}\n\n${message}\n\n**Recommended Fix:**\n${fix}${cweSection}`;
}

export function formatScaComment(finding: ScaFinding): string {
  const { package: pkg, vulnerability, reachability, confidence } = finding;
  const severityLabel = vulnerability.severity?.toUpperCase() ?? 'UNKNOWN';
  const cveId = vulnerability.id;
  const packageInfo = `${pkg.name} ${pkg.version}`;

  // Start with header: severity, package name/version, CVE ID
  let comment = `⚠️ **[${severityLabel}] ${packageInfo} — ${cveId}**`;

  // Add CWE ID label if available
  const cweMatch = vulnerability.details?.match(/CWE-(\d+)/i);
  if (cweMatch) {
    comment += ` · CWE-${cweMatch[1]}`;
  }

  // Add message/summary
  comment += `\n\n${vulnerability.summary || vulnerability.details}`;

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
  if (vulnerability.details) {
    comment += `\n\n**Fix:** Update to a patched version or apply security patches`;
  }

  return comment;
}
