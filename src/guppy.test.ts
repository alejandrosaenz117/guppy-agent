import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Guppy } from './guppy.js';
import type { LanguageModel } from 'ai';
import type { Finding } from './types.js';

// v6 doGenerate returns content: LanguageModelV2Content[] array
// tool calls use { type: 'tool-call', toolCallType: 'function', toolCallId, toolName, args: string }
function makeGeneratingModel(findings: Finding[]): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => ({
      content: [{ type: 'text', text: JSON.stringify({ findings }) }],
      finishReason: 'stop',
      usage: { inputTokens: 10, outputTokens: 10 },
      rawCall: { rawPrompt: '', rawSettings: {} },
    }),
    doStream: async () => {
      throw new Error('doStream not expected in tests');
    },
  } as unknown as LanguageModel;
}

function makeFailingModel(): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => {
      throw new Error('API unavailable');
    },
    doStream: async () => {
      throw new Error('API unavailable');
    },
  } as unknown as LanguageModel;
}

// In AI SDK v6, generateText with tools automatically handles the tool loop.
// The mock just needs to return findings text; the real tool execution happens in generateText.
function makeToolCallingModel(toolName: string, toolInput: object, findings: Finding[]): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => ({
      content: [{ type: 'text', text: JSON.stringify({ findings }) }],
      finishReason: 'stop',
      usage: { inputTokens: 10, outputTokens: 10 },
      rawCall: { rawPrompt: '', rawSettings: {} },
    }),
    doStream: async () => { throw new Error('not used'); },
  } as unknown as LanguageModel;
}

const validFinding: Finding = {
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
    const findings = await guppy.audit("SELECT * FROM users WHERE id = 'input'");
    assert.ok(Array.isArray(findings));
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
    const capturingModel: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async (options: any) => {
        const userMsg = options.prompt?.find?.((m: any) => m.role === 'user');
        if (userMsg?.content) {
          capturedPrompt = userMsg.content.map((c: any) => c.text ?? '').join('');
        }
        return {
          content: [{ type: 'text', text: JSON.stringify({ findings: [] }) }],
          finishReason: 'stop',
          usage: { inputTokens: 10, outputTokens: 10 },
          rawCall: { rawPrompt: '', rawSettings: {} },
        };
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(capturingModel);
    await guppy.audit('const x = 1;');
    assert.ok(capturedPrompt.includes('<code_diff>'), 'prompt should wrap diff in <code_diff>');
    assert.ok(capturedPrompt.includes('</code_diff>'), 'prompt should close </code_diff>');
  });

  it('audit() accepts only diff parameter (no cweIndex)', async () => {
    const guppy = new Guppy(makeGeneratingModel([]));
    // Should compile and run with a single argument — if cweIndex is required this would fail at type level
    const findings = await guppy.audit('const x = 1;');
    assert.deepEqual(findings, []);
  });

  it('system prompt does not contain <cwe_reference> block', async () => {
    let capturedSystem = '';
    const capturingModel: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async (options: any) => {
        const sysMsg = options.prompt?.find?.((m: any) => m.role === 'system');
        if (sysMsg?.content) {
          capturedSystem = Array.isArray(sysMsg.content)
            ? sysMsg.content.map((c: any) => c.text ?? '').join('')
            : sysMsg.content;
        }
        return {
          content: [{ type: 'text', text: JSON.stringify({ findings: [] }) }],
          finishReason: 'stop',
          usage: { inputTokens: 10, outputTokens: 10 },
          rawCall: { rawPrompt: '', rawSettings: {} },
        };
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(capturingModel);
    await guppy.audit('const x = 1;');
    assert.ok(!capturedSystem.includes('<cwe_reference>'), 'system prompt must not contain <cwe_reference>');
  });

  it('system prompt contains CWE hint list', async () => {
    let capturedSystem = '';
    const capturingModel: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async (options: any) => {
        const sysMsg = options.prompt?.find?.((m: any) => m.role === 'system');
        if (sysMsg?.content) {
          capturedSystem = Array.isArray(sysMsg.content)
            ? sysMsg.content.map((c: any) => c.text ?? '').join('')
            : sysMsg.content;
        }
        return {
          content: [{ type: 'text', text: JSON.stringify({ findings: [] }) }],
          finishReason: 'stop',
          usage: { inputTokens: 10, outputTokens: 10 },
          rawCall: { rawPrompt: '', rawSettings: {} },
        };
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(capturingModel);
    await guppy.audit('const x = 1;');
    assert.ok(capturedSystem.includes('CWE-79'), 'hint list should include CWE-79 (XSS)');
    assert.ok(capturedSystem.includes('CWE-89'), 'hint list should include CWE-89 (SQLi)');
    assert.ok(capturedSystem.includes('find_cwe_by_id'), 'prompt should mention find_cwe_by_id tool');
  });

  it('returns findings when model completes after a tool call', async () => {
    const guppy = new Guppy(makeToolCallingModel('find_cwe_by_id', { id: '89' }, [validFinding]));
    const findings = await guppy.audit("SELECT * FROM users WHERE id = 'input'");
    assert.ok(Array.isArray(findings));
    assert.ok(findings.length > 0);
  });

  it('skips skeptic pass and returns hunter findings directly when skepticPass is false', async () => {
    let callCount = 0;
    const countingModel: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async () => {
        callCount++;
        return {
          content: [{ type: 'text', text: JSON.stringify({ findings: [validFinding] }) }],
          finishReason: 'stop',
          usage: { inputTokens: 10, outputTokens: 10 },
          rawCall: { rawPrompt: '', rawSettings: {} },
        };
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(countingModel, false);
    const findings = await guppy.audit('const x = 1;');
    assert.equal(callCount, 1, 'model should be called exactly once (no skeptic pass)');
    assert.deepEqual(findings, [validFinding]);
  });

  it('runs skeptic pass (two model calls) when skepticPass is true', async () => {
    let callCount = 0;
    const countingModel: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async () => {
        callCount++;
        return {
          content: [{ type: 'text', text: JSON.stringify({ findings: [validFinding] }) }],
          finishReason: 'stop',
          usage: { inputTokens: 10, outputTokens: 10 },
          rawCall: { rawPrompt: '', rawSettings: {} },
        };
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(countingModel, true);
    await guppy.audit('const x = 1;');
    assert.equal(callCount, 2, 'model should be called twice (hunter + skeptic)');
  });

  it('returns empty array when model fails during tool call loop', async () => {
    let callCount = 0;
    const failAfterToolCall: LanguageModel = {
      specificationVersion: 'v2',
      provider: 'test',
      modelId: 'test-model',
      doGenerate: async () => {
        callCount++;
        if (callCount === 1) {
          return {
            content: [{
              type: 'tool-call',
              toolCallType: 'function',
              toolCallId: 'call-1',
              toolName: 'find_cwe_by_id',
              args: JSON.stringify({ id: '89' }),
            }],
            finishReason: 'tool-calls',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        }
        throw new Error('API failed on step 2');
      },
      doStream: async () => { throw new Error('not used'); },
    } as unknown as LanguageModel;

    const guppy = new Guppy(failAfterToolCall);
    const findings = await guppy.audit('const x = 1;');
    assert.deepEqual(findings, []);
  });
});

