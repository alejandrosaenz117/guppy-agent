# Remediation Guidance Design

## Goal

Surface actionable remediation in every PR comment Guppy posts:
- **SAST findings**: LLM rewrites the vulnerable code snippet and includes it in the comment
- **SCA findings**: Show the exact version to upgrade to (from OSV `fixed_version`)

---

## SAST Remediation

### Schema Change

Add `fix_snippet` to `FindingSchema` in `src/types.ts`:

```typescript
fix_snippet: z.string().max(3000).optional()
  .describe('Rewritten version of the vulnerable code that mitigates the issue')
```

`fix` retains its role as a human-readable explanation. `fix_snippet` is the actual rewrite.

### Context Window for Rewrite Accuracy

Guppy currently receives the full scrubbed diff. To produce an accurate rewrite, the hunter prompt needs the ±50-line hunk surrounding the vulnerable line extracted from the diff. This is already present in the diff itself — no GitHub API call needed. The diff hunk gives Guppy the function scope required to rewrite correctly.

### Prompt Change (`src/guppy.ts` — `hunterPrompt`)

Add to the hunter prompt's output instructions:

```
For each finding, populate fix_snippet with a concrete rewritten version of the
vulnerable code that mitigates the issue. Use the surrounding diff context (the
hunk containing the vulnerable line) to understand the function scope. The snippet
should be valid, minimal, and drop-in replaceable — not pseudocode or commentary.
If the vulnerable code is too large or too contextually dependent to rewrite safely,
omit fix_snippet.
```

The `fix` field continues to carry the explanation ("Why this is vulnerable and what the rewrite addresses"). `fix_snippet` carries the code.

### Comment Format Change (`src/enricher.ts` — `enrichFinding`)

Current format:
```
🚨 [SEVERITY] Type · CWE-ID

message

**Recommended Fix:**
fix text

CWE section
```

New format (when `fix_snippet` is present):
```
🚨 [SEVERITY] Type · CWE-ID

message

**Recommended Fix:**
fix text

**Suggested Rewrite:**
```language
fix_snippet
```

CWE section
```

Language is inferred from the file extension in `finding.file`. If extension is unrecognized, use no language tag.

---

## SCA Remediation

### No Schema Change Required

`OsvVulnerability.fixed_version` already exists and is populated by `OsvAdapter`. It is simply not used in `formatScaComment`.

### Comment Format Change (`src/enricher.ts` — `formatScaComment`)

Current fix line:
```typescript
comment += `\n\n**Fix:** Update to a patched version or apply security patches`;
```

New logic:
```typescript
if (vulnerability.fixed_version) {
  const escaped = escapeMarkdown(vulnerability.fixed_version);
  comment += `\n\n**Fix:** Upgrade \`${escapedPkgName}\` to version \`${escaped}\` or later`;
} else {
  comment += `\n\n**Fix:** Update to a patched version or apply security patches`;
}
```

The `fixed_version` value is escaped with `escapeMarkdown` before interpolation to prevent injection. The package name is already escaped as `escapedPkgName`.

---

## Data Flow (unchanged except noted)

```
SAST:
  diff → [Guppy hunter] → Finding { fix, fix_snippet } → enrichFinding() → PR comment

SCA:
  diff → [OsvAdapter] → OsvVulnerability { fixed_version } → formatScaComment() → PR comment
```

No changes to the SCA pipeline, OSV adapter, or reachability hunter. No new LLM calls for SCA. One additional field in the SAST LLM response.

---

## Error Handling

- `fix_snippet` is optional — if the LLM omits it, the comment renders without the rewrite block. No fallback logic needed.
- `fixed_version` already has a fallback (the generic message). No new failure modes.
- The Skeptic pass receives `fix_snippet` in the hunter findings and must preserve it on kept findings — no prompt change needed since Skeptic returns the full finding object.

---

## Testing

- `src/enricher.ts` tests: add cases for `fix_snippet` present vs. absent in SAST comment output
- `src/enricher.ts` tests: add cases for `fixed_version` present vs. absent in SCA comment output
- `src/guppy.ts` tests: verify `fix_snippet` flows through hunter → skeptic → output
- `src/types.ts`: `fix_snippet` field validation (max length, optional)

---

## Files Changed

| File | Change |
|------|--------|
| `src/types.ts` | Add `fix_snippet` optional field to `FindingSchema` |
| `src/guppy.ts` | Update `hunterPrompt` to instruct LLM to populate `fix_snippet` |
| `src/enricher.ts` | Update `enrichFinding` to render `fix_snippet`; update `formatScaComment` to use `fixed_version` |

No changes to: `src/index.ts`, `src/sca/`, `src/sarif.ts`, `src/scrubber.ts`.
