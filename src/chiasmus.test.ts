import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ChiasmusAnalyzer } from './chiasmus.js';
import type { Finding } from './types.js';

const validFinding: Finding = {
  file: 'src/auth.ts',
  line: 10,
  severity: 'high',
  type: 'SQL Injection',
  message: 'User input in SQL query',
  fix: 'Use parameterized queries',
};

describe('ChiasmusAnalyzer.analyze()', () => {
  it('returns ChiasmusContext with mapSummary and graphSummary strings', async () => {
    const analyzer = new ChiasmusAnalyzer();
    const ctx = await analyzer.analyze(['src/index.ts']);
    assert.ok(typeof ctx.mapSummary === 'string');
    assert.ok(typeof ctx.graphSummary === 'string');
  });

  it('calling analyze() twice reuses the cached graph (verify is callable after analyze)', async () => {
    const analyzer = new ChiasmusAnalyzer();
    await analyzer.analyze(['src/index.ts']);
    // verify() should work without re-calling analyze()
    const { results, deadCode } = await analyzer.verify([validFinding]);
    assert.ok(Array.isArray(results));
    assert.ok(Array.isArray(deadCode));
  });
});

describe('ChiasmusAnalyzer.verify()', () => {
  it('returns results array with verdict per finding', async () => {
    const analyzer = new ChiasmusAnalyzer();
    await analyzer.analyze(['src/index.ts']);
    const { results, deadCode } = await analyzer.verify([validFinding]);
    assert.ok(Array.isArray(results));
    assert.ok(Array.isArray(deadCode));
    assert.equal(results.length, 1);
    assert.ok(['reachable', 'unreachable', 'unknown'].includes(results[0].verdict));
  });

  it('returns empty arrays for empty findings input', async () => {
    const analyzer = new ChiasmusAnalyzer();
    await analyzer.analyze(['src/index.ts']);
    const { results, deadCode } = await analyzer.verify([]);
    assert.deepEqual(results, []);
    assert.deepEqual(deadCode, []);
  });

  it('dead code findings have severity none and type Dead Code', async () => {
    const analyzer = new ChiasmusAnalyzer();
    await analyzer.analyze(['src/index.ts']);
    const { deadCode } = await analyzer.verify([validFinding]);
    for (const dc of deadCode) {
      assert.equal(dc.severity, 'none');
      assert.equal(dc.type, 'Dead Code');
    }
  });
});
