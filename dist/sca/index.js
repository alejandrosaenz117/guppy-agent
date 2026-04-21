import * as core from '@actions/core';
import { extractPackagesFromDiff } from './lockfile.js';
/**
 * ScaAuditor - Orchestrates the Software Composition Analysis (SCA) pipeline
 *
 * Combines three stages:
 * 1. Package extraction from lockfile diffs
 * 2. Vulnerability scanning via ScannerAdapter
 * 3. Reachability analysis via ScaHunter (optional)
 */
export class ScaAuditor {
    adapter;
    hunter;
    preExtractedPackages;
    constructor(adapter, hunter, // null when reachability disabled
    preExtractedPackages) {
        this.adapter = adapter;
        this.hunter = hunter;
        this.preExtractedPackages = preExtractedPackages;
    }
    /**
     * Run the full SCA pipeline on a git diff
     * Returns ScaFinding[] with vulnerability and reachability information
     */
    async audit(diff) {
        // Stage 1: Extract packages from lockfile changes
        // Use pre-extracted packages if available (from raw diff before scrubbing)
        // Otherwise extract from the provided diff
        let packages = this.preExtractedPackages || extractPackagesFromDiff(diff);
        if (packages.length === 0) {
            return [];
        }
        // Cap packages at 500 to prevent DoS via unbounded package lists
        if (packages.length > 500) {
            core.warning('[Guppy SCA] Package list truncated at 500 to prevent DoS attacks');
            packages = packages.slice(0, 500);
        }
        core.info(`Detected ${packages.length} changed package(s)`);
        // Build a map of package names to lockfile paths for later enrichment
        const lockfileMap = this.buildLockfileMap(diff);
        // Stage 2: Scan packages for vulnerabilities
        let vulns;
        try {
            vulns = await this.adapter.scan(packages);
        }
        catch (error) {
            core.warning(`Vulnerability scanning failed: ${error instanceof Error ? error.message : String(error)}`);
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
            }
            catch (error) {
                // Hunter errors are already handled internally with UNKNOWN verdicts
                core.warning(`Reachability analysis error: ${error instanceof Error ? error.message : String(error)}`);
                // Fall through to direct mapping below
            }
        }
        // Stage 3b: If no hunter or hunter failed, map vulnerabilities directly to findings
        const findings = vulns.map(vuln => ({
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
     * Sanitizes file paths to prevent log injection attacks.
     * Strips :: metacharacters and other dangerous characters.
     */
    sanitisePath(path) {
        return path.replace(/::/g, '_').replace(/[^a-zA-Z0-9._\/-]/g, '_');
    }
    /**
     * Build a map of package names to their lockfile paths
     */
    buildLockfileMap(diff) {
        const lockfileMap = new Map();
        // Split by "diff --git" to get individual file diffs
        const fileDiffs = diff.split(/^diff --git /m).slice(1);
        for (const fileDiff of fileDiffs) {
            const lines = fileDiff.split('\n');
            if (lines.length === 0)
                continue;
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
                // Sanitise path before storing to prevent log injection
                lockfileMap.set(pkg.name, this.sanitisePath(filename));
            }
        }
        return lockfileMap;
    }
    /**
     * Extract filename from the first line of a file diff.
     * Format: "a/path/to/file b/path/to/file"
     */
    extractFilename(line) {
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
    isLockfile(filename) {
        if (!filename)
            return false;
        const lowerFilename = filename.toLowerCase();
        return (lowerFilename === 'package-lock.json' ||
            lowerFilename === 'yarn.lock' ||
            lowerFilename === 'pnpm-lock.yaml' ||
            lowerFilename === 'pipfile.lock' ||
            lowerFilename === 'poetry.lock' ||
            lowerFilename === 'go.sum' ||
            lowerFilename === 'cargo.lock' ||
            lowerFilename === 'gemfile.lock');
    }
    /**
     * Enrich findings with lockfile path information
     */
    enrichFindingsWithLockfilePath(findings, lockfileMap) {
        return findings.map(finding => ({
            ...finding,
            file: lockfileMap.get(finding.package.name),
        }));
    }
}
export { ScaHunter } from './hunter.js';
export { OsvAdapter } from './adapters/osv.js';
//# sourceMappingURL=index.js.map