import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import type { DetectedPackage, OsvVulnerability, ScannerAdapter, ScaFinding } from '../types.js';
import { ScaAuditor } from './index.js';
import type { ScaHunter } from './hunter.js';

/**
 * Mock ScannerAdapter that returns hardcoded vulnerabilities
 */
class MockScannerAdapter implements ScannerAdapter {
  constructor(
    private vulnsToReturn: OsvVulnerability[] = [],
    private shouldThrow: boolean = false
  ) {}

  async scan(packages: DetectedPackage[]): Promise<OsvVulnerability[]> {
    if (this.shouldThrow) {
      throw new Error('Adapter scan failed');
    }
    return this.vulnsToReturn;
  }
}

/**
 * Mock ScaHunter that returns hardcoded verdicts
 */
function createMockScaHunter(findingsToReturn: ScaFinding[] = []): ScaHunter {
  return {
    analyze: async () => findingsToReturn,
  } as any;
}

/**
 * Helper to create a mock vulnerability
 */
function createVuln(overrides?: Partial<OsvVulnerability>): OsvVulnerability {
  return {
    id: 'CVE-2023-12345',
    summary: 'Test vulnerability',
    details: 'Test details',
    affected_versions: ['<1.0.0'],
    package_name: 'lodash',
    installed_version: '4.17.20',
    severity: 'high',
    ...overrides,
  };
}

/**
 * Helper to create a mock finding
 */
function createFinding(overrides?: Partial<ScaFinding>): ScaFinding {
  return {
    package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    vulnerability: createVuln(),
    reachability: 'reachable',
    confidence: 2,
    ...overrides,
  };
}

/**
 * Helper to create a package-lock.json diff with specific packages
 */
function createPackageLockDiff(packageVersions: Record<string, string>): string {
  const packageEntries = Object.entries(packageVersions)
    .map(
      ([name, version]) => `
    "${name}": {
+      "version": "${version}",
       "resolved": "https://registry.npmjs.org/${name}/-/${name}-${version}.tgz"
     },`
    )
    .join('\n');

  return `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,10 +1,10 @@
 {
   "dependencies": {${packageEntries}
   }
 }
`;
}

describe('ScaAuditor', () => {
  let adapter: MockScannerAdapter;
  let hunter: ScaHunter | null;
  let auditor: ScaAuditor;

  beforeEach(() => {
    adapter = new MockScannerAdapter();
    hunter = null;
    auditor = new ScaAuditor(adapter, hunter);
  });

  describe('audit()', () => {
    it('returns empty array when diff contains no lockfile changes', async () => {
      const diff = `diff --git a/src/index.ts b/src/index.ts
index abc123..def456 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,5 +1,5 @@
 console.log('hello');
-const x = 1;
+const x = 2;
`;
      const result = await auditor.audit(diff);
      assert.deepEqual(result, []);
    });

    it('returns empty array when scanner finds no vulnerabilities', async () => {
      const diff = createPackageLockDiff({ lodash: '4.17.21' });
      adapter = new MockScannerAdapter([]); // No vulns
      auditor = new ScaAuditor(adapter, hunter);

      const result = await auditor.audit(diff);
      assert.deepEqual(result, []);
    });

    it('returns findings without reachability when hunter is null', async () => {
      const vuln = createVuln();
      adapter = new MockScannerAdapter([vuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = createPackageLockDiff({ lodash: '4.17.20' });
      const result = await auditor.audit(diff);

      assert.equal(result.length, 1);
      assert.equal(result[0].package.name, 'lodash');
      assert.equal(result[0].package.version, '4.17.20');
      assert.equal(result[0].vulnerability.id, 'CVE-2023-12345');
      assert.equal(result[0].reachability, undefined);
      assert.equal(result[0].confidence, undefined);
    });

    it('returns findings with reachability when hunter is provided', async () => {
      const vuln = createVuln();
      const finding = createFinding({
        vulnerability: vuln,
        reachability: 'reachable',
        confidence: 2,
      });

      adapter = new MockScannerAdapter([vuln]);
      hunter = createMockScaHunter([finding]);
      auditor = new ScaAuditor(adapter, hunter);

      const diff = createPackageLockDiff({ lodash: '4.17.20' });
      const result = await auditor.audit(diff);

      assert.equal(result.length, 1);
      assert.equal(result[0].reachability, 'reachable');
      assert.equal(result[0].confidence, 2);
    });

    it('includes lockfile path in findings', async () => {
      const vuln = createVuln();
      adapter = new MockScannerAdapter([vuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = createPackageLockDiff({ lodash: '4.17.20' });
      const result = await auditor.audit(diff);

      assert.equal(result.length, 1);
      assert.equal(result[0].file, 'package-lock.json');
    });

    it('handles multiple packages from same lockfile', async () => {
      const lodashVuln = createVuln({ package_name: 'lodash', installed_version: '4.17.20' });
      const expressVuln = createVuln({
        id: 'CVE-2023-54321',
        package_name: 'express',
        installed_version: '4.18.1',
      });

      adapter = new MockScannerAdapter([lodashVuln, expressVuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = createPackageLockDiff({ lodash: '4.17.20', express: '4.18.1' });
      const result = await auditor.audit(diff);

      assert.equal(result.length, 2);
      assert.equal(result[0].package.name, 'lodash');
      assert.equal(result[0].file, 'package-lock.json');
      assert.equal(result[1].package.name, 'express');
      assert.equal(result[1].file, 'package-lock.json');
    });

    it('catches adapter errors and returns empty array', async () => {
      adapter = new MockScannerAdapter([], true); // Should throw
      auditor = new ScaAuditor(adapter, null);

      const diff = createPackageLockDiff({ lodash: '4.17.20' });
      const result = await auditor.audit(diff);

      assert.deepEqual(result, []);
    });

    it('handles yarn.lock lockfile path', async () => {
      const vuln = createVuln();
      adapter = new MockScannerAdapter([vuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = `diff --git a/yarn.lock b/yarn.lock
index abc123..def456 100644
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,10 +1,10 @@
 # yarn lockfile v1
+"lodash@4.17.20":
+  version "4.17.20"
   resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
`;
      const result = await auditor.audit(diff);

      assert.equal(result.length, 1);
      assert.equal(result[0].file, 'yarn.lock');
    });

    it('handles go.sum lockfile path', async () => {
      const vuln = createVuln({ package_name: 'golang.org/x/sys' });
      adapter = new MockScannerAdapter([vuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = `diff --git a/go.sum b/go.sum
index abc123..def456 100644
--- a/go.sum
+++ b/go.sum
@@ -1,5 +1,5 @@
+golang.org/x/sys v0.5.0 h1:abc123...
 golang.org/x/net v0.10.0 h1:def456...
`;
      const result = await auditor.audit(diff);

      assert.equal(result.length, 1);
      assert.equal(result[0].file, 'go.sum');
    });

    it('processes multiple lockfiles in same diff', async () => {
      const lodashVuln = createVuln({ package_name: 'lodash', installed_version: '4.17.20' });
      const sysVuln = createVuln({
        id: 'CVE-2023-99999',
        package_name: 'golang.org/x/sys',
        installed_version: '0.5.0',
      });

      adapter = new MockScannerAdapter([lodashVuln, sysVuln]);
      auditor = new ScaAuditor(adapter, null);

      const npmDiff = createPackageLockDiff({ lodash: '4.17.20' });
      const goDiff = `diff --git a/go.sum b/go.sum
index abc123..def456 100644
--- a/go.sum
+++ b/go.sum
@@ -1,5 +1,5 @@
+golang.org/x/sys v0.5.0 h1:abc123...
 golang.org/x/net v0.10.0 h1:def456...
`;
      const combinedDiff = npmDiff + '\n' + goDiff;

      const result = await auditor.audit(combinedDiff);

      assert.equal(result.length, 2);
      // Check that both findings have correct file paths
      const npmFinding = result.find(f => f.package.name === 'lodash');
      const goFinding = result.find(f => f.package.name === 'golang.org/x/sys');

      assert(npmFinding);
      assert.equal(npmFinding.file, 'package-lock.json');

      assert(goFinding);
      assert.equal(goFinding.file, 'go.sum');
    });

    it('preserves vulnerability details in findings', async () => {
      const vuln = createVuln({
        id: 'CVE-2023-12345',
        summary: 'Prototype pollution vulnerability',
        details: 'This is a detailed description',
        severity: 'critical',
        cvss_score: 9.5,
        cwe_ids: ['CWE-1025'],
      });

      adapter = new MockScannerAdapter([vuln]);
      auditor = new ScaAuditor(adapter, null);

      const diff = createPackageLockDiff({ lodash: '4.17.20' });
      const result = await auditor.audit(diff);

      assert.equal(result[0].vulnerability.id, 'CVE-2023-12345');
      assert.equal(result[0].vulnerability.summary, 'Prototype pollution vulnerability');
      assert.equal(result[0].vulnerability.severity, 'critical');
      assert.equal(result[0].vulnerability.cvss_score, 9.5);
    });
  });
});
