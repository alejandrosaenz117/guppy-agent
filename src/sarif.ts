import { gzipSync } from 'zlib';
import type { Finding } from './types.js';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

function severityToLevel(severity: Finding['severity']): string {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function ruleId(finding: Finding): string {
  return finding.cwe_id ? `CWE-${finding.cwe_id}` : finding.type;
}

export function findingsToSarif(findings: Finding[], enrichedTexts?: Map<Finding, string>): any {
  const rulesMap = new Map<string, { id: string; shortDescription: { text: string }; help?: { text: string; markdown: string } }>();
  for (const f of findings) {
    const id = ruleId(f);
    if (!rulesMap.has(id)) {
      const enriched = enrichedTexts?.get(f);
      rulesMap.set(id, {
        id,
        shortDescription: { text: f.type },
        ...(enriched ? { help: { text: enriched, markdown: enriched } } : {}),
      });
    }
  }

  const results = findings.map((f) => ({
    ruleId: ruleId(f),
    level: severityToLevel(f.severity),
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file, uriBaseId: 'SRCROOT' },
          region: { startLine: f.line },
        },
      },
    ],
  }));

  return {
    version: '2.1.0',
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: 'guppy-agent',
            rules: [...rulesMap.values()],
          },
        },
        results,
      },
    ],
  };
}

export function sarifToBase64(sarif: any): string {
  return gzipSync(Buffer.from(JSON.stringify(sarif))).toString('base64');
}
