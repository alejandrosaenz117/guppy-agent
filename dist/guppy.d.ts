import type { LanguageModel } from 'ai';
import { Finding } from './types.js';
import type { ChiasmusContext } from './chiasmus.js';
export interface ChiasmusAnalyzer {
    verify(findings: Finding[]): Promise<{
        results: Array<{
            finding: Finding;
            verdict: 'reachable' | 'unreachable' | 'unknown';
        }>;
        deadCode: Finding[];
    }>;
}
export declare class Guppy {
    private model;
    constructor(model: LanguageModel);
    private buildHunterPrompt;
    private readonly skepticPrompt;
    audit(diff: string, chiasmusCtx?: ChiasmusContext | null, analyzer?: ChiasmusAnalyzer): Promise<Finding[]>;
}
//# sourceMappingURL=guppy.d.ts.map