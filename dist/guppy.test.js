import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Guppy } from './guppy.js';
// Minimal LanguageModel stub that returns controlled responses
function makeModel(response) {
    return {
        specificationVersion: 'v1',
        provider: 'test',
        modelId: 'test-model',
        defaultObjectGenerationMode: 'json',
        doGenerate: async () => {
            throw new Error('doGenerate not expected in tests');
        },
        doStream: async () => {
            throw new Error('doStream not expected in tests');
        },
    };
}
// A model that returns a valid findings array via generateObject
function makeGeneratingModel(findings) {
    return {
        specificationVersion: 'v1',
        provider: 'test',
        modelId: 'test-model',
        defaultObjectGenerationMode: 'json',
        doGenerate: async () => ({
            text: JSON.stringify(findings),
            finishReason: 'stop',
            usage: { promptTokens: 10, completionTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
        }),
        doStream: async () => {
            throw new Error('doStream not expected in tests');
        },
    };
}
// A model that always throws (simulates API failure)
function makeFailingModel() {
    return {
        specificationVersion: 'v1',
        provider: 'test',
        modelId: 'test-model',
        defaultObjectGenerationMode: 'json',
        doGenerate: async () => {
            throw new Error('API unavailable');
        },
        doStream: async () => {
            throw new Error('API unavailable');
        },
    };
}
const validFinding = {
    file: 'src/auth.ts',
    line: 10,
    severity: 'high',
    type: 'SQL Injection',
    message: 'User input used in SQL query',
    fix: 'Use parameterized queries',
};
describe('Guppy.audit()', () => {
    it('returns empty array when diff is empty string', async () => {
        const guppy = new Guppy(makeGeneratingModel([]));
        const findings = await guppy.audit('');
        assert.deepEqual(findings, []);
    });
    it('returns empty array when Hunter finds nothing', async () => {
        const guppy = new Guppy(makeGeneratingModel([]));
        const findings = await guppy.audit('const x = 1;');
        assert.deepEqual(findings, []);
    });
    it('returns empty array when model API fails', async () => {
        const guppy = new Guppy(makeFailingModel());
        const findings = await guppy.audit('const password = "hunter2";');
        assert.deepEqual(findings, []);
    });
    it('returns findings array with correct shape when vulnerabilities found', async () => {
        const guppy = new Guppy(makeGeneratingModel([validFinding, validFinding]));
        const findings = await guppy.audit('SELECT * FROM users WHERE id = ' + "'" + 'input' + "'");
        assert.ok(Array.isArray(findings));
        // Each finding should have required fields
        for (const f of findings) {
            assert.ok('file' in f);
            assert.ok('line' in f);
            assert.ok('severity' in f);
            assert.ok('type' in f);
            assert.ok('message' in f);
            assert.ok('fix' in f);
        }
    });
    it('wraps diff in code_diff XML tags before sending to model', async () => {
        let capturedPrompt = '';
        const capturingModel = {
            specificationVersion: 'v1',
            provider: 'test',
            modelId: 'test-model',
            defaultObjectGenerationMode: 'json',
            doGenerate: async (options) => {
                // Capture the prompt from the messages
                const userMsg = options.prompt?.find?.((m) => m.role === 'user');
                if (userMsg?.content) {
                    capturedPrompt = userMsg.content.map((c) => c.text ?? '').join('');
                }
                return {
                    text: '[]',
                    finishReason: 'stop',
                    usage: { promptTokens: 10, completionTokens: 10 },
                    rawCall: { rawPrompt: '', rawSettings: {} },
                };
            },
            doStream: async () => { throw new Error('not used'); },
        };
        const guppy = new Guppy(capturingModel);
        await guppy.audit('const x = 1;');
        assert.ok(capturedPrompt.includes('<code_diff>'), 'prompt should wrap diff in <code_diff>');
        assert.ok(capturedPrompt.includes('</code_diff>'), 'prompt should close </code_diff>');
    });
});
//# sourceMappingURL=guppy.test.js.map