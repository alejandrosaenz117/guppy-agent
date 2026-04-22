import { enrichFinding, _setCweListCache } from './enricher.js';

_setCweListCache([]);

const finding = {
  file: 'demo-vulnerable.js',
  line: 5,
  severity: 'critical',
  type: 'SQL Injection',
  message: 'User input is directly concatenated',
  fix: 'Use parameterized queries',
  cwe_id: '89',
};

const result = await enrichFinding(finding);
const lines = result.split('\n');
lines.forEach((line, i) => console.log(`${i.toString().padStart(3)}: ${line}`));
