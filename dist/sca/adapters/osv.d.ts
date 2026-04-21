import { DetectedPackage, OsvVulnerability, ScannerAdapter } from '../../types.js';
/**
 * OSV (Open Source Vulnerability) Scanner Adapter
 * Implements the ScannerAdapter interface to query OSV's vulnerability database
 */
export declare class OsvAdapter implements ScannerAdapter {
    private readonly apiUrl;
    /**
     * Scans packages for vulnerabilities using the OSV Batch Query API
     */
    scan(packages: DetectedPackage[]): Promise<OsvVulnerability[]>;
    /**
     * Calls the OSV Batch Query API with chunking (100 packages per request)
     */
    private queryOsvBatch;
    /**
     * Maps ecosystem names from DetectedPackage to OSV ecosystem format
     */
    private mapEcosystem;
    /**
     * Maps OSV API response to OsvVulnerability array
     */
    private mapOsvResponseToVulnerabilities;
    /**
     * Maps a single OSV vulnerability to OsvVulnerability format
     */
    private mapOsvVulnerabilityToOsvVulnerability;
}
//# sourceMappingURL=osv.d.ts.map