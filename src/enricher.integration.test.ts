import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { enrichFinding, _setCweListCache } from './enricher.js';
import type { Finding } from './types.js';

beforeEach(() => {
  _setCweListCache([]);
});

describe('enrichFinding() integration', () => {
  it('outputs complete structure with all sections', async () => {
    const finding: Finding = {
      file: 'src/auth.ts',
      line: 10,
      severity: 'high',
      type: 'SQL Injection',
      message: 'User input used in SQL query.',
      fix: 'Use parameterized queries.',
      cwe_id: '89',
    };

    const result = await enrichFinding(finding);

    console.log('=== FULL OUTPUT ===');
    console.log(result);
    console.log('=== END OUTPUT ===\n');

    // Verify all expected sections are present
    assert.ok(result.includes('🚨'), 'should have alert emoji');
    assert.ok(result.includes('**[HIGH] SQL Injection**'), 'should have severity and type');
    assert.ok(result.includes('User input used in SQL query'), 'should have message');
    assert.ok(result.includes('**Recommended Fix:**'), 'should have fix section header');
    assert.ok(result.includes('Use parameterized queries'), 'should have fix text');
    assert.ok(result.includes('**Suggested Fix**'), 'should have suggested fix header');
    assert.ok(result.includes('```ts'), 'should have ts code fence');
    assert.ok(result.includes('CWE-89'), 'should have CWE section');
  });

  it('generates code block even without fix_snippet', async () => {
    const finding: Finding = {
      file: 'src/app.js',
      line: 5,
      severity: 'critical',
      type: 'Command Injection',
      message: 'User input passed to shell.',
      fix: 'Use child_process.execFile with array arguments.',
      // NO fix_snippet
    };

    const result = await enrichFinding(finding);

    console.log('=== OUTPUT WITHOUT FIX_SNIPPET ===');
    console.log(result);
    console.log('=== END OUTPUT ===\n');

    // Key assertions
    assert.ok(result.includes('**Suggested Fix**'), 'MUST have Suggested Fix section even without fix_snippet');
    assert.ok(result.includes('```js'), 'MUST have code fence with js language');
    assert.ok(result.includes('Use child_process.execFile'), 'code block should contain fix text');
  });
});
