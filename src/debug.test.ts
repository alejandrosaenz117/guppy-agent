import { describe, it } from 'node:test';
import { enrichFinding, _setCweListCache } from './enricher.js';
import type { Finding } from './types.js';

describe('DEBUG', () => {
  it('check output structure', async () => {
    _setCweListCache([]);

    const finding: Finding = {
      file: 'demo-vulnerable.js',
      line: 5,
      severity: 'critical',
      type: 'SQL Injection',
      message: 'User input is directly concatenated into SQL query',
      fix: 'Use parameterized queries with placeholders',
      cwe_id: '89',
    };

    const result = await enrichFinding(finding);

    console.log('\n====== ACTUAL GITHUB COMMENT OUTPUT ======');
    console.log(result);
    console.log('====== END OUTPUT ======\n');

    console.log('Length:', result.length);
    console.log('Has header:', result.includes('🚨'));
    console.log('Has Recommended Fix header:', result.includes('**Recommended Fix:**'));
    console.log('Has fix text:', result.includes('Use parameterized queries'));
    console.log('Has Suggested Fix header:', result.includes('**Suggested Fix**'));
    console.log('Has opening fence:', result.includes('```'));
    console.log('Has closing fence:', result.lastIndexOf('```'));
    console.log('Has CWE section:', result.includes('**CWE-'));

    const lines = result.split('\n');
    console.log('Total lines:', lines.length);
    console.log('Line with Recommended:', lines.findIndex(l => l.includes('Recommended')));
    console.log('Line with Suggested:', lines.findIndex(l => l.includes('Suggested')));
    console.log('Line with CWE:', lines.findIndex(l => l.includes('CWE-')));
  });
});
