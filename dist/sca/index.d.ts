import type { DetectedPackage, ScannerAdapter, ScaFinding } from '../types.js';
import type { ScaHunter } from './hunter.js';
/**
 * ScaAuditor - Orchestrates the Software Composition Analysis (SCA) pipeline
 *
 * Combines three stages:
 * 1. Package extraction from lockfile diffs
 * 2. Vulnerability scanning via ScannerAdapter
 * 3. Reachability analysis via ScaHunter (optional)
 */
export declare class ScaAuditor {
    private adapter;
    private hunter;
    private preExtractedPackages?;
    constructor(adapter: ScannerAdapter, hunter: ScaHunter | null, // null when reachability disabled
    preExtractedPackages?: DetectedPackage[]);
    /**
     * Run the full SCA pipeline on a git diff
     * Returns ScaFinding[] with vulnerability and reachability information
     */
    audit(diff: string): Promise<ScaFinding[]>;
    /**
     * Sanitizes file paths to prevent log injection attacks.
     * Strips :: metacharacters and other dangerous characters.
     */
    private sanitisePath;
    /**
     * Build a map of package names to their lockfile paths
     */
    private buildLockfileMap;
    /**
     * Extract filename from the first line of a file diff.
     * Format: "a/path/to/file b/path/to/file"
     */
    private extractFilename;
    /**
     * Check if filename is a lockfile we care about
     */
    private isLockfile;
    /**
     * Enrich findings with lockfile path information
     */
    private enrichFindingsWithLockfilePath;
}
export { ScaHunter } from './hunter.js';
export { OsvAdapter } from './adapters/osv.js';
export type { ScannerAdapter, ScaFinding, OsvVulnerability } from '../types.js';
//# sourceMappingURL=index.d.ts.map