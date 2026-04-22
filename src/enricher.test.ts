import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { enrichFinding, formatScaComment, _setCweListCache } from './enricher.js';
import type { Finding, ScaFinding } from './types.js';

const baseFinding: Finding = {
  file: 'src/auth.ts',
  line: 10,
  severity: 'high',
  type: 'SQL Injection',
  message: 'User input used in SQL query.',
  fix: 'Use parameterized queries.',
};

beforeEach(() => {
  _setCweListCache([]);
});

describe('enrichFinding()', () => {
  it('renders without fix_snippet block when fix_snippet is absent', async () => {
    const result = await enrichFinding(baseFinding);
    assert.ok(!result.includes('Suggested Rewrite'), 'no rewrite block when fix_snippet absent');
  });

  it('renders Suggested Rewrite block when fix_snippet is present', async () => {
    const finding = { ...baseFinding, fix_snippet: 'const x = safeValue;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('Suggested Rewrite'), 'should include rewrite heading');
    assert.ok(result.includes('const x = safeValue;'), 'should include snippet content');
  });

  it('includes AI-generated disclaimer in rewrite block', async () => {
    const finding = { ...baseFinding, fix_snippet: 'const x = safeValue;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('AI-generated'), 'must include AI-generated disclaimer');
  });

  it('neutralizes triple-backtick sequences in fix_snippet to prevent fenced-block breakout', async () => {
    const finding = { ...baseFinding, fix_snippet: 'const x = 1;\n```\nmalicious' };
    const result = await enrichFinding(finding);
    assert.ok(!result.includes('\n```\n'), 'raw triple-backtick must not appear unmodified in output');
  });

  it('uses ts language tag for .ts files', async () => {
    const finding = { ...baseFinding, file: 'src/auth.ts', fix_snippet: 'const x = 1;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```ts\n') || result.includes('```typescript\n'), 'should use ts/typescript lang tag');
  });

  it('uses js language tag for .js files', async () => {
    const finding = { ...baseFinding, file: 'src/auth.js', fix_snippet: 'const x = 1;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```js\n') || result.includes('```javascript\n'), 'should use js/javascript lang tag');
  });

  it('uses py language tag for .py files', async () => {
    const finding = { ...baseFinding, file: 'app/views.py', fix_snippet: 'x = safe_value' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```py\n') || result.includes('```python\n'), 'should use py/python lang tag');
  });

  it('uses no language tag for unknown file extensions', async () => {
    const finding = { ...baseFinding, file: 'config.toml', fix_snippet: 'key = value' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```\n'), 'unknown extension should use plain fence');
  });

  it('rewrite block appears after fix text and before CWE section', async () => {
    const finding = { ...baseFinding, fix_snippet: 'const x = safeValue;', cwe_id: '89' };
    const result = await enrichFinding(finding);
    const fixIdx = result.indexOf('Recommended Fix');
    const rewriteIdx = result.indexOf('Suggested Rewrite');
    assert.ok(fixIdx < rewriteIdx, 'rewrite block should come after fix text');
  });
});

describe('formatScaComment()', () => {
  const baseSca: ScaFinding = {
    package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    vulnerability: {
      id: 'CVE-2021-23337',
      summary: 'Command injection in lodash',
      details: 'Prototype pollution via merge',
      severity: 'high',
      affected_versions: ['<4.17.21'],
    },
  };

  it('shows generic fix message when fixed_version is absent', () => {
    const result = formatScaComment(baseSca);
    assert.ok(result.includes('Update to a patched version'), 'fallback message when no fixed_version');
  });

  it('shows specific upgrade version when fixed_version is present', () => {
    const finding: ScaFinding = {
      ...baseSca,
      vulnerability: { ...baseSca.vulnerability, fixed_version: '4.17.21' },
    };
    const result = formatScaComment(finding);
    assert.ok(result.includes('4.17.21'), 'should include the fixed version');
    assert.ok(result.includes('Upgrade'), 'should say Upgrade');
    assert.ok(!result.includes('Update to a patched version'), 'should not use generic fallback');
  });

  it('escapes markdown in fixed_version to prevent injection', () => {
    const finding: ScaFinding = {
      ...baseSca,
      vulnerability: { ...baseSca.vulnerability, fixed_version: '4.17.21**evil**' },
    };
    const result = formatScaComment(finding);
    assert.ok(!result.includes('**evil**'), 'markdown in fixed_version must be escaped');
  });
});
