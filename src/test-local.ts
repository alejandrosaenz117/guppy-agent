import 'dotenv/config';
import { anthropic } from '@ai-sdk/anthropic';
import { Guppy } from './guppy.js';
import { getCweIndex, enrichFinding } from './enricher.js';

process.env.ANTHROPIC_API_KEY = process.env.LLM_API_KEY;

const diff = `
diff --git a/src/payments.ts b/src/payments.ts
new file mode 100644
+++ b/src/payments.ts
+import http from 'node:http';
+import { exec } from 'node:child_process';
+
+export function processPayment(req: http.IncomingMessage, res: http.ServerResponse) {
+  const url = new URL(req.url!, \`http://\${req.headers.host}\`);
+  const userId = url.searchParams.get('user_id');
+  const amount = url.searchParams.get('amount');
+  const cardNumber = url.searchParams.get('card');
+
+  exec(\`echo "Payment: user=\${userId} amount=\${amount} card=\${cardNumber}" >> /var/log/payments.log\`);
+
+  const query = \`INSERT INTO transactions (user_id, amount, card) VALUES ('\${userId}', \${amount}, '\${cardNumber}')\`;
+
+  res.setHeader('Access-Control-Allow-Origin', '*');
+  res.end(JSON.stringify({ success: true, transaction: { userId, amount, card: cardNumber } }));
+}
+
+export function getTransactionHistory(req: http.IncomingMessage, res: http.ServerResponse) {
+  const url = new URL(req.url!, \`http://\${req.headers.host}\`);
+  const userId = url.searchParams.get('user_id');
+  const query = \`SELECT * FROM transactions WHERE user_id = '\${userId}'\`;
+  res.end(\`<html><body><h1>Transactions for \${userId}</h1></body></html>\`);
+}
`;

console.log('Fetching CWE database...');
const cweIndex = await getCweIndex();
console.log(`Loaded ${cweIndex.split('\n').length} CWE entries.\n`);

const model = anthropic('claude-haiku-4-5-20251001');
const guppy = new Guppy(model);

console.log('Running Guppy audit...\n');
const findings = await guppy.audit(diff, cweIndex);

if (findings.length === 0) {
  console.log('No findings.');
} else {
  console.log(`Found ${findings.length} issue(s):\n`);
  for (const f of findings) {
    const comment = await enrichFinding(f);
    console.log('---');
    console.log(comment);
    console.log();
  }
}
