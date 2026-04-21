import { DetectedPackage } from '../types.js';
/**
 * Parses a git diff and extracts packages from lockfile changes.
 * Only includes lines that were added (starting with '+' but not '+++').
 * Returns deduplicated packages by name+version+ecosystem.
 */
export declare function extractPackagesFromDiff(diff: string): DetectedPackage[];
//# sourceMappingURL=lockfile.d.ts.map