/**
 * Maps CVSS scores to severity levels
 */
function mapCvssToSeverity(cvssScore) {
    if (cvssScore === undefined) {
        return undefined;
    }
    if (cvssScore >= 9.0) {
        return 'critical';
    }
    else if (cvssScore >= 7.0) {
        return 'high';
    }
    else if (cvssScore >= 4.0) {
        return 'medium';
    }
    else if (cvssScore > 0) {
        return 'low';
    }
    return undefined;
}
/**
 * Maps database-specific severity strings to normalized levels
 */
function mapDatabaseSeverity(severity) {
    if (!severity) {
        return undefined;
    }
    const normalized = severity.toUpperCase();
    if (normalized === 'CRITICAL') {
        return 'critical';
    }
    else if (normalized === 'HIGH') {
        return 'high';
    }
    else if (normalized === 'MODERATE' || normalized === 'MEDIUM') {
        return 'medium';
    }
    else if (normalized === 'LOW') {
        return 'low';
    }
    return undefined;
}
/**
 * Extracts CVE ID from aliases array
 * Prefers CVE- format, falls back to GHSA- format
 */
function extractCveId(aliases) {
    if (!aliases || aliases.length === 0) {
        return undefined;
    }
    // Prefer CVE- IDs
    const cveId = aliases.find(alias => alias.startsWith('CVE-'));
    if (cveId) {
        return cveId;
    }
    // Fall back to GHSA- IDs
    const ghsaId = aliases.find(alias => alias.startsWith('GHSA-'));
    if (ghsaId) {
        return ghsaId;
    }
    // Return first alias as last resort
    return aliases[0];
}
/**
 * Extracts CWE IDs from database_specific field
 */
function extractCweIds(databaseSpecific) {
    const cweIds = [];
    if (!databaseSpecific || typeof databaseSpecific !== 'object') {
        return cweIds;
    }
    const dbObj = databaseSpecific;
    const cweList = dbObj.cwe_ids;
    if (Array.isArray(cweList)) {
        for (const item of cweList) {
            if (typeof item === 'string') {
                cweIds.push(item);
            }
        }
    }
    return cweIds;
}
/**
 * Extracts the fixed version from a vulnerability's affected ranges
 */
function extractFixedVersion(affected) {
    if (!Array.isArray(affected) || affected.length === 0) {
        return undefined;
    }
    // Get the first affected range
    const range = affected[0];
    if (!range || typeof range !== 'object') {
        return undefined;
    }
    const rangeObj = range;
    const events = rangeObj.events;
    if (!Array.isArray(events)) {
        return undefined;
    }
    // Look for the first fixed event
    for (const event of events) {
        if (!event || typeof event !== 'object') {
            continue;
        }
        const eventObj = event;
        if (eventObj.fixed && typeof eventObj.fixed === 'string') {
            return eventObj.fixed;
        }
    }
    return undefined;
}
/**
 * OSV (Open Source Vulnerability) Scanner Adapter
 * Implements the ScannerAdapter interface to query OSV's vulnerability database
 */
export class OsvAdapter {
    apiUrl = 'https://api.osv.dev/v1/querybatch';
    /**
     * Scans packages for vulnerabilities using the OSV Batch Query API
     */
    async scan(packages) {
        if (!packages || packages.length === 0) {
            return [];
        }
        try {
            const response = await this.queryOsvBatch(packages);
            return this.mapOsvResponseToVulnerabilities(response, packages);
        }
        catch (error) {
            console.warn('OSV Scanner error:', error instanceof Error ? error.message : String(error));
            return [];
        }
    }
    /**
     * Calls the OSV Batch Query API with chunking (100 packages per request)
     */
    async queryOsvBatch(packages) {
        const CHUNK_SIZE = 100;
        const allVulns = [];
        for (let i = 0; i < packages.length; i += CHUNK_SIZE) {
            const chunk = packages.slice(i, i + CHUNK_SIZE);
            const queries = chunk.map(pkg => ({
                package: {
                    name: pkg.name,
                    ecosystem: this.mapEcosystem(pkg.ecosystem),
                },
                version: pkg.version,
            }));
            const response = await globalThis.fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ queries }),
                signal: AbortSignal.timeout(15000),
            });
            if (!response.ok) {
                throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
            }
            const result = (await response.json());
            if (result.results) {
                allVulns.push(...result.results);
            }
            // Add delay between chunks to avoid rate limiting (100ms)
            if (i + CHUNK_SIZE < packages.length) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        return { results: allVulns };
    }
    /**
     * Maps ecosystem names from DetectedPackage to OSV ecosystem format
     */
    mapEcosystem(ecosystem) {
        // Map common ecosystem names to OSV format
        const mapping = {
            npm: 'npm',
            PyPI: 'PyPI',
            Go: 'Go',
            Cargo: 'Crates.io',
            RubyGems: 'RubyGems',
        };
        return mapping[ecosystem] || ecosystem;
    }
    /**
     * Maps OSV API response to OsvVulnerability array
     */
    mapOsvResponseToVulnerabilities(response, packages) {
        const vulnerabilities = [];
        const packageMap = new Map(packages.map(p => [`${p.name}|${p.version}`, p]));
        if (!response.results || response.results.length === 0) {
            return vulnerabilities;
        }
        for (let i = 0; i < response.results.length; i++) {
            const result = response.results[i];
            const pkg = packages[i];
            if (!result.vulns || result.vulns.length === 0) {
                continue;
            }
            for (const vuln of result.vulns) {
                const mappedVuln = this.mapOsvVulnerabilityToOsvVulnerability(vuln, pkg);
                vulnerabilities.push(mappedVuln);
            }
        }
        return vulnerabilities;
    }
    /**
     * Maps a single OSV vulnerability to OsvVulnerability format
     */
    mapOsvVulnerabilityToOsvVulnerability(osvVuln, pkg) {
        // Determine severity: CVSS score takes precedence
        let severity = mapCvssToSeverity(osvVuln.severity?.score);
        if (!severity) {
            severity = mapDatabaseSeverity(osvVuln.database_specific?.severity);
        }
        const cweIds = extractCweIds(osvVuln.database_specific);
        return {
            id: extractCveId(osvVuln.aliases) || osvVuln.id,
            summary: osvVuln.summary || '',
            details: osvVuln.details || '',
            severity,
            affected_versions: osvVuln.affected?.map(a => (a.versions || []).join(', ')).filter(Boolean) || [],
            cvss_score: osvVuln.severity?.score,
            package_name: pkg.name,
            installed_version: pkg.version,
            fixed_version: extractFixedVersion(osvVuln.affected),
            vulnerable_function: undefined,
            cwe_ids: cweIds.length > 0 ? cweIds : undefined,
        };
    }
}
//# sourceMappingURL=osv.js.map