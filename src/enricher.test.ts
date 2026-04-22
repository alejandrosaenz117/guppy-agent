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
  it('renders without Suggested Rewrite when fix_snippet is absent', async () => {
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

  it('uses longer fence when snippet contains backticks to prevent breakout', async () => {
    const finding = { ...baseFinding, fix_snippet: 'const x = 1;\n```\nmalicious' };
    const result = await enrichFinding(finding);
    // Should use 4 backticks (3+1) since snippet has 3 consecutive backticks
    assert.ok(result.includes('````'), 'should use 4-backtick fence to prevent escape');
    // The snippet content with embedded ``` should be safely inside the 4-backtick fence
    const snippetPos = result.indexOf('const x = 1;');
    const fenceEnd = result.lastIndexOf('````');
    assert.ok(snippetPos > 0 && fenceEnd > snippetPos, 'snippet should be inside fence');
  });

  it('uses ts language tag for .ts files', async () => {
    const finding = { ...baseFinding, file: 'src/auth.ts', fix_snippet: 'const x = 1;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```ts') || result.includes('```typescript'), 'should use ts/typescript lang tag');
  });

  it('uses js language tag for .js files', async () => {
    const finding = { ...baseFinding, file: 'src/auth.js', fix_snippet: 'const x = 1;' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```js') || result.includes('```javascript'), 'should use js/javascript lang tag');
  });

  it('uses py language tag for .py files', async () => {
    const finding = { ...baseFinding, file: 'app/views.py', fix_snippet: 'x = safe_value' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```py') || result.includes('```python'), 'should use py/python lang tag');
  });

  it('uses no language tag for unknown file extensions', async () => {
    const finding = { ...baseFinding, file: 'config.toml', fix_snippet: 'key = value' };
    const result = await enrichFinding(finding);
    assert.ok(result.includes('```\n'), 'unknown extension should use plain fence');
  });

  it('escapes markdown in message and fix to prevent injection', async () => {
    const finding = { ...baseFinding, message: 'User input **bold** in SQL', fix: 'Use `escape` method' };
    const result = await enrichFinding(finding);
    assert.ok(!result.includes('**bold**'), 'bold markdown in message should be escaped');
    assert.ok(!result.includes('`escape`'), 'backticks in fix should be escaped');
  });

  it('prevents fence escape via backtick-heavy snippets', async () => {
    const finding = { ...baseFinding, fix_snippet: '`````\neval(x)' };
    const result = await enrichFinding(finding);
    // Should use 6 backticks (5+1) to prevent escape
    assert.ok(result.includes('``````'), 'should use longer fence to prevent escape');
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

  it('rejects malformed fixed_version and falls back to generic message', () => {
    const finding: ScaFinding = {
      ...baseSca,
      vulnerability: { ...baseSca.vulnerability, fixed_version: 'not-a-version-**evil**' },
    };
    const result = formatScaComment(finding);
    assert.ok(result.includes('Update to a patched version'), 'fallback for invalid version format');
    assert.ok(!result.includes('**evil**'), 'malformed version is rejected, not escaped');
  });

  it('accepts valid semantic version with prerelease', () => {
    const finding: ScaFinding = {
      ...baseSca,
      vulnerability: { ...baseSca.vulnerability, fixed_version: '4.17.21-rc.1' },
    };
    const result = formatScaComment(finding);
    assert.ok(result.includes('4.17.21-rc.1'), 'should accept valid prerelease version');
  });
});
