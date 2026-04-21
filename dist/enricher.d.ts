import { CWEEntry } from 'fetch-cwe-list';
import { Enrichable, ScaFinding, Finding } from './types.js';
export declare function getCweList(): Promise<CWEEntry[]>;
declare function setCweListCache(list: CWEEntry[] | null): void;
export { setCweListCache as _setCweListCache };
export declare function enrichFinding(finding: Finding | (Enrichable & {
    severity?: string;
    type?: string;
    message?: string;
    fix?: string;
    cwe_id?: string;
})): Promise<string>;
export declare function formatScaComment(finding: ScaFinding): string;
//# sourceMappingURL=enricher.d.ts.map