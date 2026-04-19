import * as core from '@actions/core';
import cweModule, { CWEEntry } from 'fetch-cwe-list';
const fetchCweList: () => Promise<CWEEntry[]> = (cweModule as any).default ?? cweModule;
function findById(list: CWEEntry[], id: string): CWEEntry | undefined {
  return list.find((c) => c.ID === id);
}
import { Finding } from './types.js';

let cweListCache: CWEEntry[] | null = null;

async function getCweList(): Promise<CWEEntry[]> {
  if (cweListCache) return cweListCache;
  cweListCache = await fetchCweList();
  return cweListCache!;
}

export async function getCweIndex(): Promise<string> {
  try {
    const list = await getCweList();
    return list.map((c) => `CWE-${c.ID}: ${c.Name}`).join('\n');
  } catch (err) {
    core.debug('[Guppy] Failed to fetch CWE list for prompt: ' + err);
    return '';
  }
}

export async function enrichFinding(finding: Finding): Promise<string> {
  const { severity, type, message, fix, cwe_id } = finding;
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

  const cweLabel = rawId ? ` · CWE-${rawId}` : '';
  return `🚨 **[${severity.toUpperCase()}] ${type}**${cweLabel}\n\n${message}\n\n**Recommended Fix:**\n${fix}${cweSection}`;
}
