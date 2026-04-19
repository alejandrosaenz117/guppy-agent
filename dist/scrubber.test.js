import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Scrubber } from './scrubber.js';
// Real-format secrets that secretlint's preset actually detects
const ANTHROPIC_KEY = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAAA';
const SLACK_TOKEN = 'xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx';
describe('Scrubber', () => {
    describe('scrub()', () => {
        it('returns empty string unchanged', async () => {
            const s = new Scrubber();
            assert.equal(await s.scrub(''), '');
        });
        it('returns clean code unchanged', async () => {
            const s = new Scrubber();
            const input = 'const x = 1;\nfunction foo() { return x; }';
            assert.equal(await s.scrub(input), input);
        });
        it('does not corrupt diff text with no secrets', async () => {
            const s = new Scrubber();
            const input = 'diff --git a/foo.ts b/foo.ts\n+const x = process.env.API_URL;';
            const result = await s.scrub(input);
            assert.equal(result, input);
        });
        it('redacts an Anthropic API key', async () => {
            const s = new Scrubber();
            const input = `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}`;
            const result = await s.scrub(input);
            assert.ok(!result.includes(ANTHROPIC_KEY), 'Anthropic key should be redacted');
            assert.ok(result.includes('[REDACTED]'), 'should contain [REDACTED]');
        });
        it('redacts a Slack bot token', async () => {
            const s = new Scrubber();
            const input = `slack_token = ${SLACK_TOKEN}`;
            const result = await s.scrub(input);
            assert.ok(!result.includes(SLACK_TOKEN), 'Slack token should be redacted');
            assert.ok(result.includes('[REDACTED]'), 'should contain [REDACTED]');
        });
        it('redacts multiple secrets in one string', async () => {
            const s = new Scrubber();
            const input = [
                `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}`,
                `slack_token=${SLACK_TOKEN}`,
            ].join('\n');
            const result = await s.scrub(input);
            assert.ok(!result.includes(ANTHROPIC_KEY), 'Anthropic key should be redacted');
            assert.ok(!result.includes(SLACK_TOKEN), 'Slack token should be redacted');
        });
        it('preserves surrounding non-secret text when redacting', async () => {
            const s = new Scrubber();
            const input = `before\nANTHROPIC_API_KEY=${ANTHROPIC_KEY}\nafter`;
            const result = await s.scrub(input);
            assert.ok(result.includes('before'), 'text before secret should be preserved');
            assert.ok(result.includes('after'), 'text after secret should be preserved');
        });
        it('preserves structure of diff output after redaction', async () => {
            const s = new Scrubber();
            const input = [
                'diff --git a/config.ts b/config.ts',
                `+const key = "${ANTHROPIC_KEY}";`,
                '+const name = "guppy";',
            ].join('\n');
            const result = await s.scrub(input);
            assert.ok(result.includes('diff --git'), 'diff header should be preserved');
            assert.ok(result.includes('guppy'), 'unrelated content should be preserved');
            assert.ok(!result.includes(ANTHROPIC_KEY), 'secret should be redacted');
        });
    });
});
//# sourceMappingURL=scrubber.test.js.map