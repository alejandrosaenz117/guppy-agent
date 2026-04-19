import type { LanguageModel } from 'ai';
import { Finding } from './types.js';
export declare class Guppy {
    private model;
    constructor(model: LanguageModel);
    private buildHunterPrompt;
    private readonly skepticPrompt;
    audit(diff: string, cweIndex: string): Promise<Finding[]>;
}
//# sourceMappingURL=guppy.d.ts.map