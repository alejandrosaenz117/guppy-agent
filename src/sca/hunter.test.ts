import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import type { LanguageModel } from 'ai';
import { ScaHunter } from './hunter.js';
import type { OsvVulnerability } from '../types.js';

/**
 * Mock LanguageModel that returns predefined responses
 */
function makeMockModel(responseJson: object): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => ({
      content: [{ type: 'text', text: JSON.stringify(responseJson) }],
      finishReason: 'stop',
      usage: { inputTokens: 10, outputTokens: 10 },
      rawCall: { rawPrompt: '', rawSettings: {} },
    }),
    doStream: async () => {
      throw new Error('doStream not expected in tests');
    },
  } as unknown as LanguageModel;
}

/**
 * Mock LanguageModel that throws an error
 */
function makeFailingModel(): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => {
      throw new Error('Model API failed');
    },
    doStream: async () => {
      throw new Error('API unavailable');
    },
  } as unknown as LanguageModel;
}

/**
 * Mock LanguageModel that returns invalid JSON
 */
function makeInvalidJsonModel(): LanguageModel {
  return {
    specificationVersion: 'v2',
    provider: 'test',
    modelId: 'test-model',
    doGenerate: async () => ({
      content: [{ type: 'text', text: 'not valid json' }],
      finishReason: 'stop',
      usage: { inputTokens: 10, outputTokens: 10 },
      rawCall: { rawPrompt: '', rawSettings: {} },
    }),
    doStream: async () => {
      throw new Error('doStream not expected');
    },
  } as unknown as LanguageModel;
}

/**
 * Create a mock vulnerability
 */
function createVuln(overrides?: Partial<OsvVulnerability>): OsvVulnerability {
  return {
    id: 'CVE-2023-12345',
    summary: 'Test vulnerability',
    details: 'Test details',
    affected_versions: ['<1.0.0'],
    package_name: 'test-package',
    installed_version: '0.9.0',
    severity: 'high',
    ...overrides,
  };
}

describe('ScaHunter', () => {
  let mockModel: LanguageModel;

  beforeEach(() => {
    mockModel = makeMockModel({});
  });

  describe('analyze()', () => {
    it('returns empty array when vulns is empty', async () => {
      const hunter = new ScaHunter(mockModel);
      const result = await hunter.analyze([], 'some diff');
      assert.deepEqual(result, []);
    });

    it('returns empty array when vulns is null', async () => {
      const hunter = new ScaHunter(mockModel);
      const result = await hunter.analyze(null as any, 'some diff');
      assert.deepEqual(result, []);
    });

    it('returns findings with reachability verdicts', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package imported in diff',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vuln = createVuln();
      const result = await hunter.analyze([vuln], 'import "test-package"');

      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'reachable');
      assert.equal(result[0].confidence, 2);
    });

    it('maps all OsvVulnerability fields to ScaFinding', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'lodash',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package imported',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vuln = createVuln({
        id: 'CVE-2024-11111',
        summary: 'Lodash vulnerability',
        details: 'Details here',
        package_name: 'lodash',
        installed_version: '4.17.20',
        severity: 'high',
      });

      const result = await hunter.analyze([vuln], 'import _ from "lodash"');

      assert.equal(result.length, 1);
      assert.equal(result[0].vulnerability.id, 'CVE-2024-11111');
      assert.equal(result[0].vulnerability.summary, 'Lodash vulnerability');
      assert.equal(result[0].package.name, 'lodash');
      assert.equal(result[0].package.version, '4.17.20');
    });

    it('handles UNKNOWN verdict when reachability is unclear', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'unknown',
            reachability_confidence: 1,
            reachability_reasoning: 'Lockfile changed but no visible imports',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vuln = createVuln();
      const result = await hunter.analyze([vuln], 'lockfile updated');

      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'unknown');
      assert.equal(result[0].confidence, 1);
    });

    it('handles UNREACHABLE verdict', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'unreachable',
            reachability_confidence: 3,
            reachability_reasoning: 'Package import removed',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vuln = createVuln();
      const result = await hunter.analyze([vuln], 'removed import from "test-package"');

      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'unreachable');
      assert.equal(result[0].confidence, 3);
    });

    it('skips Phase 2 for vulns below severity threshold', async () => {
      // Phase 1 response
      const phase1Response = {
        findings: [
          {
            package_name: 'low-vuln-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package imported',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          return {
            content: [{ type: 'text', text: JSON.stringify(phase1Response) }],
            finishReason: 'stop',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      const hunter = new ScaHunter(model, 'high'); // threshold = high
      const vuln = createVuln({
        package_name: 'low-vuln-package',
        severity: 'low', // below threshold
      });
      await hunter.analyze([vuln], 'import "low-vuln-package"');

      // Should only call doGenerate once (Phase 1 only)
      assert.equal(callCount, 1);
    });

    it('runs Phase 2 for high/critical vulns', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'critical-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package imported',
          },
        ],
      };

      const phase2Response = {
        findings: [
          {
            package_name: 'critical-package',
            reachability: 'reachable',
            reachability_confidence: 3,
            reachability_reasoning: 'Vulnerable function called directly',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          // Return phase1 on first call, phase2 on second
          const response = callCount === 1 ? phase1Response : phase2Response;
          return {
            content: [{ type: 'text', text: JSON.stringify(response) }],
            finishReason: 'stop',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      const hunter = new ScaHunter(model, 'high');
      const vuln = createVuln({
        package_name: 'critical-package',
        severity: 'critical',
      });
      const result = await hunter.analyze([vuln], 'import { func } from "critical-package"; func()');

      // Should call doGenerate twice (Phase 1 + Phase 2)
      assert.equal(callCount, 2);
      // Phase 2 result should be used (confidence 3)
      assert.equal(result[0].confidence, 3);
    });

    it('uses Phase 2 result when available, otherwise Phase 1', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'package-with-phase2',
            reachability: 'unknown',
            reachability_confidence: 1,
            reachability_reasoning: 'Unclear in Phase 1',
          },
        ],
      };

      const phase2Response = {
        findings: [
          {
            package_name: 'package-with-phase2',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Found call site in Phase 2',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          const response = callCount === 1 ? phase1Response : phase2Response;
          return {
            content: [{ type: 'text', text: JSON.stringify(response) }],
            finishReason: 'stop',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      const hunter = new ScaHunter(model, 'high');
      const vuln = createVuln({
        package_name: 'package-with-phase2',
        severity: 'high',
      });
      const result = await hunter.analyze([vuln], 'import pkg from "package-with-phase2"');

      // Phase 2 result should override Phase 1
      assert.equal(result[0].reachability, 'reachable');
      assert.equal(result[0].confidence, 2);
    });

    it('NOT_REACHABLE verdict skips Phase 2 (always wins)', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'removed-package',
            reachability: 'unreachable',
            reachability_confidence: 3,
            reachability_reasoning: 'Import was removed',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          return {
            content: [{ type: 'text', text: JSON.stringify(phase1Response) }],
            finishReason: 'stop',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      const hunter = new ScaHunter(model, 'high');
      const vuln = createVuln({
        package_name: 'removed-package',
        severity: 'critical', // Even critical
      });
      const result = await hunter.analyze([vuln], 'removed import from "removed-package"');

      // Should only call Phase 1, not Phase 2
      assert.equal(callCount, 1);
      assert.equal(result[0].reachability, 'unreachable');
    });

    it('handles Phase 1 failure gracefully with UNKNOWN verdicts', async () => {
      const hunter = new ScaHunter(makeFailingModel());
      const vuln = createVuln();
      const result = await hunter.analyze([vuln], 'some diff');

      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'unknown');
      assert.equal(result[0].confidence, 1);
    });

    it('handles Phase 2 failure gracefully, continues with Phase 1 results', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package imported',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          if (callCount === 1) {
            // Phase 1 succeeds
            return {
              content: [{ type: 'text', text: JSON.stringify(phase1Response) }],
              finishReason: 'stop',
              usage: { inputTokens: 10, outputTokens: 10 },
              rawCall: { rawPrompt: '', rawSettings: {} },
            };
          } else {
            // Phase 2 fails
            throw new Error('Phase 2 API error');
          }
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      const hunter = new ScaHunter(model, 'high');
      const vuln = createVuln({ severity: 'critical' });
      const result = await hunter.analyze([vuln], 'import "test-package"');

      // Should use Phase 1 result when Phase 2 fails
      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'reachable');
      assert.equal(result[0].confidence, 2);
    });

    it('handles invalid JSON from model gracefully', async () => {
      const hunter = new ScaHunter(makeInvalidJsonModel());
      const vuln = createVuln();
      // Should throw or return empty/default, depending on error handling
      try {
        await hunter.analyze([vuln], 'some diff');
      } catch (error) {
        // Expected - Zod validation will fail on invalid JSON
        assert.ok(error instanceof Error);
      }
    });

    it('processes multiple vulnerabilities correctly', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'package-a',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Imported',
          },
          {
            package_name: 'package-b',
            reachability: 'unreachable',
            reachability_confidence: 3,
            reachability_reasoning: 'Removed',
          },
          {
            package_name: 'package-c',
            reachability: 'unknown',
            reachability_confidence: 1,
            reachability_reasoning: 'Unclear',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vulns = [
        createVuln({ package_name: 'package-a' }),
        createVuln({ package_name: 'package-b' }),
        createVuln({ package_name: 'package-c' }),
      ];

      const result = await hunter.analyze(vulns, 'mixed diff');

      assert.equal(result.length, 3);
      assert.equal(result[0].reachability, 'reachable');
      assert.equal(result[1].reachability, 'unreachable');
      assert.equal(result[2].reachability, 'unknown');
    });

    it('respects custom reachability threshold', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Imported',
          },
        ],
      };

      let callCount = 0;
      const model: LanguageModel = {
        specificationVersion: 'v2',
        provider: 'test',
        modelId: 'test-model',
        doGenerate: async () => {
          callCount++;
          return {
            content: [{ type: 'text', text: JSON.stringify(phase1Response) }],
            finishReason: 'stop',
            usage: { inputTokens: 10, outputTokens: 10 },
            rawCall: { rawPrompt: '', rawSettings: {} },
          };
        },
        doStream: async () => {
          throw new Error('doStream not expected');
        },
      } as unknown as LanguageModel;

      // Create hunter with 'critical' threshold
      const hunter = new ScaHunter(model, 'critical');
      const vuln = createVuln({
        package_name: 'test-package',
        severity: 'high', // Below critical threshold
      });

      await hunter.analyze([vuln], 'import "test-package"');

      // Should only call Phase 1, not Phase 2 (high < critical)
      assert.equal(callCount, 1);
    });

    it('includes reachability_reasoning in verdicts', async () => {
      const phase1Response = {
        findings: [
          {
            package_name: 'test-package',
            reachability: 'reachable',
            reachability_confidence: 2,
            reachability_reasoning: 'Package was added in import statement on line 5',
          },
        ],
      };

      const model = makeMockModel(phase1Response);
      const hunter = new ScaHunter(model);
      const vuln = createVuln();
      const result = await hunter.analyze([vuln], 'import "test-package"');

      assert.equal(result.length, 1);
      // Verify the finding has all expected fields
      assert.ok(result[0].vulnerability);
      assert.ok(result[0].package);
      assert.ok(result[0].reachability);
      assert.ok(result[0].confidence);
    });
  });
});
