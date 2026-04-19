# Chiasmus Structural Analysis Integration

**Date:** 2026-04-19  
**Status:** Approved  
**Chiasmus repo:** https://github.com/yogthos/chiasmus

## Goal

Integrate [chiasmus](https://github.com/yogthos/chiasmus) into guppy-agent to improve token efficiency, performance, and finding quality on PR scans. Chiasmus provides call graph analysis, taint flow tracking, dead code detection, and formal SMT/Prolog verification via direct Node.js imports (no MCP server, no subprocess).

## Pipeline Change

**Before:**
```
raw diff → scrub → Hunter (LLM) → Skeptic (LLM) → findings
```

**After (structural_analysis=true):**
```
raw diff → scrub → extract touched files
                 → ChiasmusAnalyzer.analyze(touchedFiles)
                     → chiasmus_map   → compact codebase outline
                     → chiasmus_graph → taint paths scoped to diff lines
                 → Guppy.audit(diff, chiasmusCtx)
                     → Hunter (LLM, enriched with <codebase_context>)
                     → ChiasmusAnalyzer.verify(hunterFindings)
                         → reachable/unreachable verdict per finding
                         → dead code findings (severity: 'none')
                     → drop unreachable findings
                     → append dead code findings
```

**After (structural_analysis=false, default):**
```
raw diff → scrub → Hunter (LLM) → Skeptic (LLM) → findings
```
Zero behavior change from today.

## New Flag

| Input | Default | Description |
| --- | --- | --- |
| `structural_analysis` | `false` | Run [chiasmus](https://github.com/yogthos/chiasmus) graph + taint analysis on diff files. Reduces false positives, surfaces dead code. Requires `chiasmus` npm package installed in the Action environment. |

Added to `ActionInputsSchema` in `src/types.ts`:
```ts
structural_analysis: z.boolean().default(false)
```

## New Components

### `src/chiasmus.ts` — ChiasmusAnalyzer

```ts
interface ChiasmusContext {
  mapSummary: string;    // compact codebase outline from chiasmus_map
  graphSummary: string;  // taint paths intersecting diff lines from chiasmus_graph
}

interface VerificationResult {
  finding: Finding;
  verdict: 'reachable' | 'unreachable' | 'unknown';
}

class ChiasmusAnalyzer {
  analyze(files: string[]): Promise<ChiasmusContext>
  verify(findings: Finding[]): Promise<{ results: VerificationResult[], deadCode: Finding[] }>
}
```

- `analyze()` calls chiasmus direct Node.js imports (`chiasmus/graph`, `chiasmus/formalize`) on the provided file list
- `verify()` calls `chiasmus/solvers` (Z3/Prolog) per Hunter finding to determine reachability; also extracts dead code findings from graph output
- Dead code findings use existing `Finding` type: `severity: 'none'`, `type: 'Dead Code'`, no `cwe_id`
- Any chiasmus error is caught, logged as a warning, and returns `null` so guppy degrades gracefully

### `src/guppy.ts` — Modified Guppy

- `audit(diff: string, chiasmusCtx: ChiasmusContext | null): Promise<Finding[]>`
- If `chiasmusCtx` present: inject map+graph summaries into Hunter system prompt as a `<codebase_context>` block; replace Skeptic LLM pass with `ChiasmusAnalyzer.verify()`
- If `chiasmusCtx` is null: run Skeptic LLM pass as today (full degradation)

### `src/index.ts` — Modified Orchestration

- Extract touched file paths from diff headers (lines starting with `diff --git`)
- If `structural_analysis=true`: instantiate `ChiasmusAnalyzer`, call `analyze(touchedFiles)`, pass result to `guppy.audit()`
- If chiasmus fails: `chiasmusCtx = null`, log warning, continue

## Degradation Rules

| Condition | Behavior |
| --- | --- |
| `structural_analysis=false` | Current behavior, chiasmus never imported |
| `structural_analysis=true`, chiasmus succeeds | Full pipeline: map+graph in, verify out |
| `structural_analysis=true`, chiasmus throws | Log warning, fall back to Skeptic LLM pass |

No file count guards. No token caps. User is responsible for managing PR size.

## README Updates

- Add `structural_analysis` to the Inputs table with link to https://github.com/yogthos/chiasmus
- Add a "Structural Analysis" section under "How it works" explaining the two-phase enhancement: richer Hunter context in, formal verification out
- Note that `chiasmus` must be available as an npm dependency when `structural_analysis=true`

## Future Extension

Full-repo scan on merge to main is out of scope. When built, `ChiasmusAnalyzer.analyze()` accepts a repo root path instead of a file list — the interface is shaped for this already.
