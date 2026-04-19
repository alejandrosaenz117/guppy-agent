import { extractGraph, buildOverview, runAnalysisFromGraph, renderMap } from 'chiasmus/graph';
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
        // If no findings provided, return empty results and no dead code
        if (findings.length === 0) {
            return { results: [], deadCode: [] };
        }
        // Convert each finding to a VerificationResult
        const results = findings.map((finding) => {
            // For now, mark all findings as 'unknown' since we don't have a specific
            // reachability check for individual findings. In a real implementation,
            // we'd run a reachability analysis targeting the finding's location.
            return {
                finding,
                verdict: 'unknown',
            };
        });
        // Convert dead code set to Finding objects (only when findings are provided)
        const deadCode = Array.from(this.deadCodeSet).map((symbol) => ({
            file: symbol, // symbol is the dead code name, not a file path
            line: 0,
            severity: 'none',
            type: 'Dead Code',
            message: `Function or class '${symbol}' is unreachable from any entry point`,
            fix: 'Remove this unused code or add an entry point that calls it',
        }));
        return { results, deadCode };
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