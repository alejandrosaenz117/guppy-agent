import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { OsvAdapter } from './osv.js';
import { DetectedPackage } from '../../types.js';

describe('OsvAdapter', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('scan', () => {
    it('returns empty array for empty packages', async () => {
      const adapter = new OsvAdapter();
      const result = await adapter.scan([]);
      assert.deepEqual(result, []);
    });

    it('returns empty array when no vulnerabilities found', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const packages: DetectedPackage[] = [
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
      ];

      const result = await adapter.scan(packages);
      assert.deepEqual(result, []);
    });

    it('maps single vulnerability from OSV response', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-1234-5678-9012',
                    aliases: ['CVE-2023-12345'],
                    summary: 'Test vulnerability',
                    details: 'This is a test vulnerability',
                    severity: {
                      type: 'CVSS_V3',
                      score: 7.5,
                    },
                    affected: [
                      {
                        package: {
                          ecosystem: 'npm',
                          name: 'lodash',
                        },
                        versions: ['<4.17.21'],
                        events: [
                          { introduced: '0' },
                          { fixed: '4.17.21' },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const packages: DetectedPackage[] = [
        { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      ];

      const result = await adapter.scan(packages);

      assert.equal(result.length, 1);
      assert.equal(result[0].id, 'CVE-2023-12345');
      assert.equal(result[0].summary, 'Test vulnerability');
      assert.equal(result[0].severity, 'high');
      assert.equal(result[0].package_name, 'lodash');
      assert.equal(result[0].installed_version, '4.17.20');
      assert.equal(result[0].fixed_version, '4.17.21');
    });

    it('prefers CVE ID over GHSA ID when both present', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-1234-5678-9012',
                    aliases: ['CVE-2023-12345', 'GHSA-abcd-efgh-ijkl'],
                    summary: 'Test',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].id, 'CVE-2023-12345');
    });

    it('uses GHSA ID when no CVE ID present', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-1234-5678-9012',
                    aliases: ['GHSA-abcd-efgh-ijkl'],
                    summary: 'Test',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].id, 'GHSA-abcd-efgh-ijkl');
    });

    it('falls back to vulnerability ID when no aliases present', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'OSV-2023-12345',
                    summary: 'Test',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].id, 'OSV-2023-12345');
    });

    describe('CVSS score to severity mapping', () => {
      it('maps 9.0+ to critical', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      severity: { score: 9.5 },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'critical');
      });

      it('maps 7.0-8.9 to high', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      severity: { score: 7.5 },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'high');
      });

      it('maps 4.0-6.9 to medium', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      severity: { score: 5.5 },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'medium');
      });

      it('maps 0.1-3.9 to low', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      severity: { score: 2.5 },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'low');
      });
    });

    describe('database_specific severity fallback', () => {
      it('uses database_specific severity when CVSS not available', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      database_specific: {
                        severity: 'HIGH',
                      },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'high');
      });

      it('maps MODERATE to medium', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      database_specific: {
                        severity: 'MODERATE',
                      },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'medium');
      });

      it('prefers CVSS score over database_specific severity', async () => {
        const mockFetch = async () => {
          return {
            ok: true,
            json: async () => ({
              results: [
                {
                  vulns: [
                    {
                      id: 'CVE-2023-12345',
                      summary: 'Test',
                      severity: { score: 7.5 },
                      database_specific: {
                        severity: 'LOW',
                      },
                      affected: [{ events: [] }],
                    },
                  ],
                },
              ],
            }),
          } as Response;
        };

        globalThis.fetch = mockFetch as typeof globalThis.fetch;

        const adapter = new OsvAdapter();
        const result = await adapter.scan([
          { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
        ]);

        assert.equal(result[0].severity, 'high');
      });
    });

    it('extracts CWE IDs from database_specific', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    summary: 'Test',
                    database_specific: {
                      cwe_ids: ['CWE-79', 'CWE-89'],
                    },
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.deepEqual((result[0] as any).cwe_ids, ['CWE-79', 'CWE-89']);
    });

    it('extracts fixed version from affected ranges', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    summary: 'Test',
                    affected: [
                      {
                        events: [
                          { introduced: '0' },
                          { fixed: '2.0.0' },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.5.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].fixed_version, '2.0.0');
    });

    it('handles fetch error gracefully', async () => {
      globalThis.fetch = async () => {
        throw new Error('Network error');
      };

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.deepEqual(result, []);
    });

    it('handles non-ok HTTP response', async () => {
      globalThis.fetch = async () => {
        return {
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
        } as Response;
      };

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.deepEqual(result, []);
    });

    it('processes multiple packages', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    aliases: ['CVE-2023-12345'],
                    summary: 'Vulnerability in lodash',
                    affected: [{ events: [] }],
                  },
                ],
              },
              {
                vulns: [
                  {
                    id: 'CVE-2023-54321',
                    aliases: ['CVE-2023-54321'],
                    summary: 'Vulnerability in express',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const packages: DetectedPackage[] = [
        { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
        { name: 'express', version: '4.18.1', ecosystem: 'npm' },
      ];

      const result = await adapter.scan(packages);

      assert.equal(result.length, 2);
      assert.equal(result[0].id, 'CVE-2023-12345');
      assert.equal(result[0].package_name, 'lodash');
      assert.equal(result[1].id, 'CVE-2023-54321');
      assert.equal(result[1].package_name, 'express');
    });

    it('processes multiple vulnerabilities per package', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    aliases: ['CVE-2023-12345'],
                    summary: 'First vulnerability',
                    affected: [{ events: [] }],
                  },
                  {
                    id: 'CVE-2023-54321',
                    aliases: ['CVE-2023-54321'],
                    summary: 'Second vulnerability',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result.length, 2);
      assert.equal(result[0].summary, 'First vulnerability');
      assert.equal(result[1].summary, 'Second vulnerability');
    });

    it('includes CVSS score in response', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    summary: 'Test',
                    severity: { score: 7.5 },
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].cvss_score, 7.5);
    });

    it('includes summary in response', async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'CVE-2023-12345',
                    summary: 'Test vulnerability summary',
                    affected: [{ events: [] }],
                  },
                ],
              },
            ],
          }),
        } as Response;
      };

      globalThis.fetch = mockFetch as typeof globalThis.fetch;

      const adapter = new OsvAdapter();
      const result = await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'npm' },
      ]);

      assert.equal(result[0].summary, 'Test vulnerability summary');
    });

    it('maps ecosystem names correctly', async () => {
      let capturedBody: string | null = null;

      globalThis.fetch = async (_url: string, options?: RequestInit) => {
        if (options?.body) {
          capturedBody = options.body as string;
        }
        return {
          ok: true,
          json: async () => ({
            results: [{ vulns: [] }],
          }),
        } as Response;
      };

      const adapter = new OsvAdapter();
      await adapter.scan([
        { name: 'pkg', version: '1.0.0', ecosystem: 'Cargo' },
      ]);

      assert.ok(capturedBody);
      const body = JSON.parse(capturedBody);
      assert.equal(body.queries[0].package.ecosystem, 'Crates.io');
    });
  });
});
