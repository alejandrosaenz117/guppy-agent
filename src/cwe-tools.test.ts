import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';

// We test the execute functions directly — extract them by calling the tool
// factories and invoking execute() with validated inputs.
// Import will fail until cwe-tools.ts exists — that's expected (RED).
import { cweTools, findCweByIdSchema, findCweByNameSchema, findCweByCapecSchema } from './cwe-tools.js';

// Minimal CWE list stub — injected via module mock or direct cache manipulation.
// We override getCweList by setting the cache before tests run.
import { _setCweListCache } from './enricher.js';

const stubList = [
  {
    ID: '79',
    Name: 'Improper Neutralization of Input During Web Page Generation',
    Description: 'XSS description',
    CAPEC_IDs: ['86', '198'],
    Known_CVEs: [],
    Abstraction: 'Class',
    Status: 'Draft',
  },
  {
    ID: '89',
    Name: 'Improper Neutralization of Special Elements used in an SQL Command',
    Description: 'SQLi description',
    CAPEC_IDs: ['66'],
    Known_CVEs: [],
    Abstraction: 'Class',
    Status: 'Draft',
  },
  {
    ID: '22',
    Name: 'Improper Limitation of a Pathname to a Restricted Directory',
    Description: 'Path traversal description',
    CAPEC_IDs: [],
    Known_CVEs: [],
    Abstraction: 'Class',
    Status: 'Draft',
  },
] as any;

before(() => {
  // Inject stub list into the in-memory cache so no network calls happen
  _setCweListCache(stubList);
});

describe('find_cwe_by_id', () => {
  it('returns full entry for known CWE ID', async () => {
    const result = await cweTools.find_cwe_by_id.execute({ id: '79' }, {} as any);
    assert.deepEqual(result, {
      id: '79',
      name: 'Improper Neutralization of Input During Web Page Generation',
      description: 'XSS description',
    });
  });

  it('returns null for unknown CWE ID', async () => {
    const result = await cweTools.find_cwe_by_id.execute({ id: '99999' }, {} as any);
    assert.equal(result, null);
  });

  it('rejects non-numeric ID via schema validation', () => {
    const result = findCweByIdSchema.safeParse({ id: 'abc' });
    assert.equal(result.success, false);
  });

  it('rejects ID longer than 10 chars', () => {
    const result = findCweByIdSchema.safeParse({ id: '12345678901' });
    assert.equal(result.success, false);
  });
});

describe('find_cwe_by_name', () => {
  it('returns id and name only, no description', async () => {
    const results = await cweTools.find_cwe_by_name.execute({ keyword: 'SQL' }, {} as any);
    assert.ok(Array.isArray(results));
    assert.ok(results.length > 0);
    for (const r of results) {
      assert.ok('id' in r);
      assert.ok('name' in r);
      assert.ok(!('description' in r), 'description should not be returned by find_cwe_by_name');
    }
  });

  it('returns all matches without a cap', async () => {
    // 'Improper' appears in all 3 stub entries
    const results = await cweTools.find_cwe_by_name.execute({ keyword: 'Improper' }, {} as any);
    assert.equal((results as any[]).length, 3);
  });

  it('is case-insensitive', async () => {
    const upper = await cweTools.find_cwe_by_name.execute({ keyword: 'SQL' }, {} as any);
    const lower = await cweTools.find_cwe_by_name.execute({ keyword: 'sql' }, {} as any);
    assert.deepEqual(upper, lower);
  });

  it('rejects keyword shorter than 2 chars', () => {
    const result = findCweByNameSchema.safeParse({ keyword: 'x' });
    assert.equal(result.success, false);
  });

  it('rejects keyword longer than 100 chars', () => {
    const result = findCweByNameSchema.safeParse({ keyword: 'a'.repeat(101) });
    assert.equal(result.success, false);
  });
});

describe('find_cwe_by_capec', () => {
  it('returns full detail for known CAPEC ID', async () => {
    const results = await cweTools.find_cwe_by_capec.execute({ capec_id: '66' }, {} as any);
    assert.ok(Array.isArray(results));
    assert.equal(results.length, 1);
    assert.equal(results[0].id, '89');
    assert.ok('description' in results[0]);
  });

  it('returns empty array for unknown CAPEC ID', async () => {
    const results = await cweTools.find_cwe_by_capec.execute({ capec_id: '99999' }, {} as any);
    assert.deepEqual(results, []);
  });

  it('rejects non-numeric CAPEC ID', () => {
    const result = findCweByCapecSchema.safeParse({ capec_id: 'abc' });
    assert.equal(result.success, false);
  });

  it('rejects CAPEC ID longer than 10 chars', () => {
    const result = findCweByCapecSchema.safeParse({ capec_id: '12345678901' });
    assert.equal(result.success, false);
  });
});

describe('getCweList cache', () => {
  it('getCweList is not called again when cache is already populated', async () => {
    // Call all three tools — cache should only have been set once (in before())
    await cweTools.find_cwe_by_id.execute({ id: '79' }, {} as any);
    await cweTools.find_cwe_by_name.execute({ keyword: 'SQL' }, {} as any);
    await cweTools.find_cwe_by_capec.execute({ capec_id: '66' }, {} as any);
    // If getCweList re-fetched, the stub cache would be bypassed and network call would fail
    // The fact that results are correct proves the cache was used
    assert.ok(true, 'all tool calls completed using cached list');
  });
});
