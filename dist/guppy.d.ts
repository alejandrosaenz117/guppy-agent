import type { LanguageModel } from 'ai';
import { Finding } from './types';
export declare class Guppy {
    private model;
    constructor(model: LanguageModel);
    private readonly hunterPrompt;
    private readonly skepticPrompt;
    audit(diff: string): Promise<Finding[]>;
}
//# sourceMappingURL=guppy.d.ts.map