import { extractGraph, buildOverview, runAnalysisFromGraph, renderMap, buildFileDetail, detectEntryPoints } from 'chiasmus/graph';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
export class ChiasmusAnalyzer {
    cachedGraph = null;
    deadCodeSet = new Set();
    /**
     * Analyze source files and build a cached call graph.
     * Must be called before verify().
     */
    async analyze(filePaths) {
        // Read files from disk
        const files = filePaths.map((filePath) => {
            const absolutePath = resolve(filePath);
            const content = readFileSync(absolutePath, 'utf-8');
            return { path: filePath, content };
        });
        // Extract the call graph
        this.cachedGraph = await extractGraph(files);
        // Build overview map and render to markdown
        const overview = buildOverview(this.cachedGraph);
        const mapSummary = renderMap(overview, 'markdown');
        // Run summary and dead-code analyses
        const summaryResult = await runAnalysisFromGraph(this.cachedGraph, {
            analysis: 'summary',
        });
        // Get dead code
        const deadCodeResult = await runAnalysisFromGraph(this.cachedGraph, {
            analysis: 'dead-code',
        });
        // Extract dead code list and cache it
        if (Array.isArray(deadCodeResult.result)) {
            this.deadCodeSet = new Set(deadCodeResult.result);
        }
        // Format graph summary
        const graphSummary = this.formatGraphSummary(summaryResult, deadCodeResult);
        return { mapSummary, graphSummary };
    }
    /**
     * Verify findings against the cached graph.
     * Returns reachability verdict for each finding + dead code findings.
     * Must be called after analyze().
     */
    async verify(findings) {
        if (!this.cachedGraph) {
            throw new Error('Graph not analyzed. Call analyze() with source files first.');
        }
        if (findings.length === 0) {
            return { results: [], deadCode: [] };
        }
        // Detect entry points once for all reachability queries
        const entryPoints = detectEntryPoints(this.cachedGraph);
        const results = await Promise.all(findings.map(async (finding) => {
            const symbol = this.resolveSymbolAtLocation(finding.file, finding.line);
            if (!symbol) {
                return { finding, verdict: 'unknown' };
            }
            // If the symbol itself is dead code, mark unreachable immediately
            if (this.deadCodeSet.has(symbol)) {
                return { finding, verdict: 'unreachable' };
            }
            // Check if any entry point can reach this symbol
            const reachable = await this.isReachableFromAnyEntryPoint(symbol, entryPoints);
            return { finding, verdict: reachable ? 'reachable' : 'unreachable' };
        }));
        const deadCode = Array.from(this.deadCodeSet).map((symbol) => ({
            file: symbol,
            line: 0,
            severity: 'none',
            type: 'Dead Code',
            message: `Function or class '${symbol}' is unreachable from any entry point`,
            fix: 'Remove this unused code or add an entry point that calls it',
        }));
        return { results, deadCode };
    }
    resolveSymbolAtLocation(file, line) {
        if (!this.cachedGraph)
            return null;
        const fileDetail = buildFileDetail(this.cachedGraph, file);
        if (!fileDetail || !fileDetail.symbols?.length)
            return null;
        // Find the symbol whose definition is closest to (but not after) the finding line
        const candidates = fileDetail.symbols
            .filter(s => s.line <= line)
            .sort((a, b) => b.line - a.line);
        return candidates[0]?.name ?? null;
    }
    async isReachableFromAnyEntryPoint(symbol, entryPoints) {
        if (!this.cachedGraph || entryPoints.length === 0)
            return true;
        for (const entry of entryPoints) {
            try {
                const result = await runAnalysisFromGraph(this.cachedGraph, {
                    analysis: 'reachability',
                    from: entry,
                    to: symbol,
                });
                if (result.result?.reachable === true)
                    return true;
            }
            catch {
                // Individual check failed — don't penalize the finding
            }
        }
        return false;
    }
    formatGraphSummary(summaryResult, deadCodeResult) {
        const lines = [];
        lines.push('# Graph Summary');
        // Add summary info
        if (summaryResult.result && typeof summaryResult.result === 'object') {
            const summary = summaryResult.result;
            lines.push('');
            lines.push('## Statistics');
            if (summary.definitions) {
                lines.push(`- Definitions: ${summary.definitions}`);
            }
            if (summary.calls) {
                lines.push(`- Call relationships: ${summary.calls}`);
            }
            if (summary.files) {
                lines.push(`- Files analyzed: ${summary.files}`);
            }
        }
        // Add dead code info
        if (deadCodeResult.result &&
            Array.isArray(deadCodeResult.result) &&
            deadCodeResult.result.length > 0) {
            lines.push('');
            lines.push('## Dead Code Detected');
            lines.push(`Found ${deadCodeResult.result.length} unreachable symbol(s):`);
            deadCodeResult.result.slice(0, 10).forEach((symbol) => {
                lines.push(`- ${symbol}`);
            });
            if (deadCodeResult.result.length > 10) {
                lines.push(`- ... and ${deadCodeResult.result.length - 10} more`);
            }
        }
        return lines.join('\n');
    }
}
//# sourceMappingURL=chiasmus.js.map