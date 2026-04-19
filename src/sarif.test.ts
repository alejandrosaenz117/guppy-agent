import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { findingsToSarif } from './sarif.js';
import type { Finding } from './types.js';

const base: Finding = {
  file: 'src/auth.ts',
  line: 42,
  severity: 'high',
  type: 'SQL Injection',
  message: 'User input concatenated into SQL query.',
  fix: 'Use parameterized queries.',
  cwe_id: '89',
};

describe('findingsToSarif()', () => {
  it('returns a valid SARIF 2.1.0 document', () => {
    const sarif = findingsToSarif([base]);
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.$schema.includes('sarif-schema-2.1.0'));
    assert.ok(Array.isArray(sarif.runs));
    assert.equal(sarif.runs.length, 1);
  });

  it('sets tool driver name to guppy-agent', () => {
    const sarif = findingsToSarif([base]);
    assert.equal(sarif.runs[0].tool.driver.name, 'guppy-agent');
  });

  it('produces one result per finding', () => {
    const sarif = findingsToSarif([base, { ...base, line: 99, type: 'XSS', cwe_id: '79' }]);
    assert.equal(sarif.runs[0].results.length, 2);
  });

  it('produces zero results for empty findings', () => {
    const sarif = findingsToSarif([]);
    assert.equal(sarif.runs[0].results.length, 0);
  });

  it('maps critical severity to error level', () => {
    const sarif = findingsToSarif([{ ...base, severity: 'critical' }]);
    assert.equal(sarif.runs[0].results[0].level, 'error');
  });

  it('maps high severity to error level', () => {
    const sarif = findingsToSarif([{ ...base, severity: 'high' }]);
    assert.equal(sarif.runs[0].results[0].level, 'error');
  });

  it('maps medium severity to warning level', () => {
    const sarif = findingsToSarif([{ ...base, severity: 'medium' }]);
    assert.equal(sarif.runs[0].results[0].level, 'warning');
  });

  it('maps low severity to note level', () => {
    const sarif = findingsToSarif([{ ...base, severity: 'low' }]);
    assert.equal(sarif.runs[0].results[0].level, 'note');
  });

  it('maps none severity to note level', () => {
    const sarif = findingsToSarif([{ ...base, severity: 'none' }]);
    assert.equal(sarif.runs[0].results[0].level, 'note');
  });

  it('uses CWE ID as ruleId when present', () => {
    const sarif = findingsToSarif([{ ...base, cwe_id: '89' }]);
    assert.equal(sarif.runs[0].results[0].ruleId, 'CWE-89');
  });

  it('falls back to type as ruleId when cwe_id is absent', () => {
    const { cwe_id, ...noCwe } = base;
    const sarif = findingsToSarif([noCwe]);
    assert.equal(sarif.runs[0].results[0].ruleId, 'SQL Injection');
  });

  it('sets message text from finding message', () => {
    const sarif = findingsToSarif([base]);
    assert.equal(sarif.runs[0].results[0].message.text, base.message);
  });

  it('sets physical location uri from finding file', () => {
    const sarif = findingsToSarif([base]);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.artifactLocation.uri, 'src/auth.ts');
  });

  it('sets region startLine from finding line', () => {
    const sarif = findingsToSarif([base]);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.startLine, 42);
  });

  it('includes a rule entry in driver.rules for each unique ruleId', () => {
    const sarif = findingsToSarif([
      { ...base, cwe_id: '89' },
      { ...base, cwe_id: '89', line: 10 },
      { ...base, cwe_id: '79', type: 'XSS' },
    ]);
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: any) => r.id);
    assert.ok(ruleIds.includes('CWE-89'));
    assert.ok(ruleIds.includes('CWE-79'));
    assert.equal(ruleIds.length, 2);
  });

  it('rule description uses finding type', () => {
    const sarif = findingsToSarif([base]);
    const rule = sarif.runs[0].tool.driver.rules[0];
    assert.equal(rule.shortDescription.text, 'SQL Injection');
  });

  it('sets artifactLocation uriBaseId to SRCROOT', () => {
    const sarif = findingsToSarif([base]);
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
    assert.equal(uri.uriBaseId, 'SRCROOT');
  });
});
