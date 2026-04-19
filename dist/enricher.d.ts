import { CWEEntry } from 'fetch-cwe-list';
import { Finding } from './types.js';
export declare function getCweList(): Promise<CWEEntry[]>;
declare function setCweListCache(list: CWEEntry[] | null): void;
export { setCweListCache as _setCweListCache };
export declare function enrichFinding(finding: Finding): Promise<string>;
//# sourceMappingURL=enricher.d.ts.map