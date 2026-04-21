import * as core from '@actions/core';
import { extractPackagesFromDiff } from './lockfile.js';
import type { DetectedPackage, OsvVulnerability, ScannerAdapter, ScaFinding } from '../types.js';
import type { ScaHunter } from './hunter.js';

/**
 * ScaAuditor - Orchestrates the Software Composition Analysis (SCA) pipeline
 *
 * Combines three stages:
 * 1. Package extraction from lockfile diffs
 * 2. Vulnerability scanning via ScannerAdapter
 * 3. Reachability analysis via ScaHunter (optional)
 */
export class ScaAuditor {
  constructor(
    private adapter: ScannerAdapter,
    private hunter: ScaHunter | null, // null when reachability disabled
  ) {}

  /**
   * Run the full SCA pipeline on a git diff
   * Returns ScaFinding[] with vulnerability and reachability information
   */
  async audit(diff: string): Promise<ScaFinding[]> {
    // Stage 1: Extract packages from lockfile changes
    const packages = extractPackagesFromDiff(diff);

    if (packages.length === 0) {
      return [];
    }

    core.info(`Detected ${packages.length} changed package(s)`);

    // Build a map of package names to lockfile paths for later enrichment
    const lockfileMap = this.buildLockfileMap(diff);

    // Stage 2: Scan packages for vulnerabilities
    let vulns: OsvVulnerability[];
    try {
      vulns = await this.adapter.scan(packages);
    } catch (error) {
      core.warning(
        `Vulnerability scanning failed: ${error instanceof Error ? error.message : String(error)}`
      );
      return [];
    }

    if (vulns.length === 0) {
      return [];
    }

    core.info(`Found ${vulns.length} vulnerability(ies)`);

    // Stage 3: Run reachability analysis if hunter is available
    if (this.hunter) {
      core.info('Running reachability analysis...');
      try {
        const findings = await this.hunter.analyze(vulns, diff);
        return this.enrichFindingsWithLockfilePath(findings, lockfileMap);
      } catch (error) {
        // Hunter errors are already handled internally with UNKNOWN verdicts
        core.warning(
          `Reachability analysis error: ${error instanceof Error ? error.message : String(error)}`
        );
        // Fall through to direct mapping below
      }
    }

    // Stage 3b: If no hunter or hunter failed, map vulnerabilities directly to findings
    const findings: ScaFinding[] = vulns.map(vuln => ({
      package: {
        name: vuln.package_name || '',
        version: vuln.installed_version || '',
        ecosystem: 'npm', // TODO: extract from vuln if available
      },
      vulnerability: vuln,
      reachability: undefined,
      confidence: undefined,
    }));

    return this.enrichFindingsWithLockfilePath(findings, lockfileMap);
  }

  /**
   * Build a map of package names to their lockfile paths
   */
  private buildLockfileMap(diff: string): Map<string, string> {
    const lockfileMap = new Map<string, string>();

    // Split by "diff --git" to get individual file diffs
    const fileDiffs = diff.split(/^diff --git /m).slice(1);

    for (const fileDiff of fileDiffs) {
      const lines = fileDiff.split('\n');
      if (lines.length === 0) continue;

      // First line contains the file paths: a/path b/path
      const firstLine = lines[0];
      const filename = this.extractFilename(firstLine);

      // Detect ecosystem from filename to validate it's a lockfile
      if (!this.isLockfile(filename)) {
        continue;
      }

      // Extract packages from this lockfile to map them
      const packages = extractPackagesFromDiff(`diff --git ${firstLine}\n${lines.slice(1).join('\n')}`);
      for (const pkg of packages) {
        lockfileMap.set(pkg.name, filename);
      }
    }

    return lockfileMap;
  }

  /**
   * Extract filename from the first line of a file diff.
   * Format: "a/path/to/file b/path/to/file"
   */
  private extractFilename(line: string): string {
    const parts = line.split(' b/');
    if (parts.length < 2) {
      return '';
    }
    const aPath = parts[0].replace(/^a\//, '');
    return aPath;
  }

  /**
   * Check if filename is a lockfile we care about
   */
  private isLockfile(filename: string): boolean {
    if (!filename) return false;

    const lowerFilename = filename.toLowerCase();
    return (
      lowerFilename === 'package-lock.json' ||
      lowerFilename === 'yarn.lock' ||
      lowerFilename === 'pnpm-lock.yaml' ||
      lowerFilename === 'pipfile.lock' ||
      lowerFilename === 'poetry.lock' ||
      lowerFilename === 'go.sum' ||
      lowerFilename === 'cargo.lock' ||
      lowerFilename === 'gemfile.lock'
    );
  }

  /**
   * Enrich findings with lockfile path information
   */
  private enrichFindingsWithLockfilePath(
    findings: ScaFinding[],
    lockfileMap: Map<string, string>
  ): ScaFinding[] {
    return findings.map(finding => ({
      ...finding,
      file: lockfileMap.get(finding.package.name),
    }));
  }
}

export { ScaHunter } from './hunter.js';
export { OsvAdapter } from './adapters/osv.js';
export type { ScannerAdapter, ScaFinding, OsvVulnerability } from '../types.js';
