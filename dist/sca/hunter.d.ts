import type { LanguageModel } from 'ai';
import type { OsvVulnerability, ScaFinding } from '../types.js';
/**
 * ScaHunter - LLM-powered reachability analysis for supply chain vulnerabilities
 *
 * Implements two-phase analysis:
 * Phase 1: Import-level detection (all CVEs)
 * Phase 2: Call-site detection (high/critical by default, configurable)
 */
export declare class ScaHunter {
    private model;
    private reachabilityThreshold;
    private readonly phase1System;
    private readonly phase2System;
    constructor(model: LanguageModel, reachabilityThreshold?: string);
    /**
     * Analyze vulnerabilities for reachability in the given diff
     *
     * Two-phase approach:
     * Phase 1: Import-level detection (all CVEs)
     * Phase 2: Call-site detection (high/critical by default, configurable)
     */
    analyze(vulns: OsvVulnerability[], diff: string): Promise<ScaFinding[]>;
    /**
     * Phase 1: Import-level detection
     */
    private phase1;
    /**
     * Phase 2: Call-site detection
     */
    private phase2;
}
//# sourceMappingURL=hunter.d.ts.map