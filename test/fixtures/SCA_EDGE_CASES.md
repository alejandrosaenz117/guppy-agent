# SCA Pipeline Edge Cases & Robustness Testing

This document describes edge cases and boundary conditions for the Supply Chain Attack (SCA) security scanning pipeline. These test cases ensure robust handling of malformed inputs, unusual OSV API responses, and complex reachability analysis scenarios.

## Table of Contents

1. [Lockfile Edge Cases](#lockfile-edge-cases)
2. [OSV Response Edge Cases](#osv-response-edge-cases)
3. [Reachability Analysis Edge Cases](#reachability-analysis-edge-cases)
4. [Configuration Edge Cases](#configuration-edge-cases)
5. [Integration Edge Cases](#integration-edge-cases)

---

## Lockfile Edge Cases

### 1. Empty Lockfile

**Fixture:** `empty-lockfile.json`

**Description:** A valid `package-lock.json` file with an empty dependencies object.

```json
{
  "lockfileVersion": 2,
  "packages": {
    "": {
      "dependencies": {}
    }
  }
}
```

**Expected Behavior:**
- No packages to analyze
- SCA pipeline should gracefully skip dependency scanning
- No OSV queries required
- Action item: PR should pass without SCA findings

**Use Case:** Testing graceful handling of projects with no external dependencies.

---

### 2. Massive Lockfile

**Fixture:** `massive-lockfile.json`

**Description:** A lockfile with 5000+ packages (simplified to demonstrate capping logic).

**Expected Behavior:**
- Pipeline should cap analysis at 500 packages (implementation-dependent)
- Efficiency testing: verify no performance degradation
- Memory usage remains bounded
- Processing time is acceptable (< 30s for 500 package subset)

**Use Case:** Testing scalability limits and performance under heavy load.

**Configuration Impact:**
- May trigger rate limiting with OSV API
- Requires batch processing or caching strategy
- Consider timeout handling for large queries

---

### 3. Malformed Lockfile

**Fixture:** `malformed-lockfile.json`

**Description:** Lockfile with invalid JSON syntax and null/missing fields.

**Examples:**
- Null version fields: `"version": null`
- Invalid package specifiers: `"broken@package]@2.0.0"`
- Missing required properties
- Invalid enum values

**Expected Behavior:**
- Parser should validate JSON structure
- Invalid entries should be skipped with logging
- Pipeline continues with valid entries
- Error messages should be informative

**Use Case:** Testing error resilience and graceful degradation.

---

### 4. Duplicate Package Entries

**Fixture:** `duplicate-packages-lockfile.json`

**Description:** Lockfile with the same package listed multiple times (different versions or specifications).

```json
{
  "dependencies": {
    "lodash": "4.17.21",
    "lodash@4.17.21": "4.17.21"
  }
}
```

**Expected Behavior:**
- Deduplication: same package@version should be processed once
- Different versions of same package should each be analyzed separately
- No duplicate findings in final report
- Maintain order of first occurrence

**Use Case:** Testing deduplication and version resolution logic.

---

### 5. Mixed Valid + Invalid Entries

**Fixture:** `malformed-lockfile.json` (combined with other test data)

**Description:** Lockfile where some entries are valid and others are malformed.

**Expected Behavior:**
- Process valid entries normally
- Skip invalid entries with appropriate logging
- Report which packages were skipped
- Final results only include valid entries
- Pipeline does not fail completely

**Use Case:** Testing partial failure recovery.

---

## OSV Response Edge Cases

### 1. Empty Response

**Fixture:** `osv-edge-cases.json` - `empty_response`

**Description:** OSV API returns 0 vulnerabilities for queried packages.

```json
{
  "results": []
}
```

**Expected Behavior:**
- No SCA findings generated
- PR should pass (unless other SAST findings exist)
- Log confirmation that packages were checked
- Confidence should be HIGH (verified safe)

**Use Case:** Testing happy path with no vulnerabilities.

---

### 2. Oversized Response

**Fixture:** `osv-edge-cases.json` - `oversized_response`

**Description:** OSV response with extremely long summary/details fields (>10KB per vulnerability).

**Expected Behavior:**
- Summaries should be truncated for display (e.g., first 500 chars)
- Full details stored internally if needed
- Comment posting should handle truncation gracefully
- No buffer overflows or memory issues

**Configuration:** May need `osv_summary_max_length` parameter

**Use Case:** Testing handling of verbose OSV data.

---

### 3. Missing Fields

**Fixture:** `osv-edge-cases.json` - `missing_fields`

**Description:** OSV response with null or missing critical fields.

**Examples:**
- `cve_id: null`
- `versions: [null, "1.0.0"]`
- Missing `affected` array
- Missing `severity` field

**Expected Behavior:**
- Gracefully handle null/missing fields
- Use defaults where appropriate (e.g., severity = "UNKNOWN")
- Generate findings with available data
- Log warnings about missing fields
- Findings should still be actionable

**Use Case:** Testing defensive programming against API inconsistencies.

---

### 4. Invalid CVSS Scores

**Fixture:** `osv-edge-cases.json` - `invalid_cvss`

**Description:** CVSS scores that are invalid, out-of-range, or malformed.

**Examples:**
- `score: "invalid-score"` (string instead of number)
- `score: 15.5` (out of range 0-10)
- `score: -1.0` (negative)
- `vector: "INVALID_VECTOR_STRING"` (malformed CVSS vector)

**Expected Behavior:**
- Parse failures should not crash pipeline
- Use severity level as fallback when CVSS fails
- Log malformed CVSS data
- Treat as valid vulnerability regardless

**Use Case:** Testing parsing robustness.

---

### 5. Misaligned Results Length

**Fixture:** `osv-edge-cases.json` - `misaligned_results`

**Description:** OSV returns results count that doesn't match input packages.

**Example:** Query 10 packages, get 3 results (maybe one package has multiple vulns).

**Expected Behavior:**
- Correct: results can be fewer than inputs (one package, multiple vulns)
- Correct: results can have different package counts (one vuln affects many)
- Verify all queried packages are represented in results
- Flag packages with no results (clean) vs. packages in results (vulnerable)

**Use Case:** Testing result matching logic.

---

### 6. Duplicate Vulnerabilities

**Fixture:** `osv-edge-cases.json` - `duplicate_vulnerabilities`

**Description:** Same CVE appears multiple times in OSV response.

**Expected Behavior:**
- Deduplicate by CVE ID
- Merge affected packages from duplicates
- Only one finding per CVE in final report
- Maintain complete package list

**Use Case:** Testing deduplication of OSV response data.

---

## Reachability Analysis Edge Cases

### 1. No Imports in Diff

**Fixture:** `reachability-edge-cases.json` - `no_imports_diff`

**Description:** Git diff that only changes values/logic, with no dependency imports.

```diff
-const value = 'old value';
+const value = 'new value';
```

**Expected Behavior:**
- All vulnerable packages marked as NOT_REACHABLE
- No LLM reachability phase needed
- Findings should be suppressed (unless `fail_on_severity: 'all'`)
- Phase 2 skipped to save LLM costs

**Use Case:** Testing optimization: skip LLM when no imports detected.

---

### 2. Dynamic Imports Only

**Fixture:** `reachability-edge-cases.json` - `dynamic_imports_only`

**Description:** Diff with dynamic imports: `await import('pkg-' + var)`, `require(...)`.

**Expected Behavior:**
- Cannot determine statically which packages are used
- Reachability: UNCERTAIN
- Should trigger Phase 2 (LLM reachability analysis)
- LLM evaluates likelihood based on code context
- Confidence lower than static imports

**Use Case:** Testing handling of dynamic code patterns.

---

### 3. Aliased Imports

**Fixture:** `reachability-edge-cases.json` - `aliased_imports`

**Description:** Imports using aliases or namespace patterns.

```javascript
import * as _ from 'lodash';
import { max as maximum } from 'mathjs';
```

**Expected Behavior:**
- Correctly identify `lodash` and `mathjs` as imported
- Reachability: FOUND_IN_SOURCE (imports are static)
- Alias handling in Phase 2 LLM analysis
- Findings should be included

**Use Case:** Testing alias resolution and import pattern recognition.

---

### 4. Mixed Severity Levels

**Fixture:** `reachability-edge-cases.json` - `mixed_severity_levels`

**Description:** Multiple packages with CRITICAL, HIGH, MEDIUM, and LOW severity vulnerabilities.

**Expected Behavior:**
- Filtering by `sca_reachability_confidence_threshold`:
  - Threshold 1.0 (most permissive): all included
  - Threshold 0.5 (moderate): CRITICAL and HIGH included
  - Threshold 0.1 (strict): only CRITICAL
- Findings organized by severity
- LOW severity filtered unless reachable

**Use Case:** Testing severity-based filtering and prioritization.

---

### 5. High Diff Size (Near 500KB Limit)

**Fixture:** `reachability-edge-cases.json` - `large_diff_near_limit`

**Description:** Git diff approaching 500KB size limit.

**Metrics:**
- Size: ~498KB
- Lines: ~12,500
- Files changed: ~150
- Imports: multiple from lodash, axios, express, react, typescript

**Expected Behavior:**
- Successfully process diff up to limit
- Warn if approaching limit
- Fail gracefully if exceeds (reject PR with message)
- Cache diff analysis for efficiency

**Use Case:** Testing boundary condition handling.

---

### 6. No Source Files in Diff

**Fixture:** `reachability-edge-cases.json` - `no_source_files_diff`

**Description:** Diff only modifies non-source files (package.json, README.md, etc.).

**Expected Behavior:**
- No imports detected in non-source files
- All packages: NOT_REACHABLE
- Findings suppressed
- PR should pass
- Log: "No source code changes detected"

**Use Case:** Testing correct handling of non-code changes.

---

## Configuration Edge Cases

### 1. SCA Reachability Disabled

**Configuration:**
```yaml
sca_reachability: false
```

**Expected Behavior:**
- Phase 1: OSV scanning performed normally
- Phase 2: LLM reachability analysis SKIPPED
- All findings treated as reachable (worst-case assumption)
- Findings based on severity alone
- PR fails if any vulnerability found (configurable via `fail_on_severity`)

**Use Case:** Testing cost-optimization mode (skip LLM analysis).

---

### 2. Reachability Threshold: Low

**Configuration:**
```yaml
sca_reachability: true
sca_reachability_threshold: 'low'
```

**Expected Behavior:**
- ALL packages analyzed in Phase 2
- LLM evaluates each package even if not imported
- Lower confidence bar for reachability determination
- More findings flagged as reachable
- Useful for comprehensive audits

**Use Case:** Testing aggressive vulnerability detection.

---

### 3. Confidence Threshold: Most Permissive

**Configuration:**
```yaml
sca_reachability_confidence_threshold: 1
```

**Expected Behavior:**
- Most findings included (even low confidence)
- LLM scores > 1% = reachable
- Few findings suppressed
- Max audit coverage
- May have false positives

**Use Case:** Testing high-sensitivity configuration.

---

### 4. Fail on Severity: None

**Configuration:**
```yaml
fail_on_severity: 'none'
```

**Expected Behavior:**
- PR always passes, even with CRITICAL vulnerabilities
- Findings still reported in comment
- Useful for tracking/reporting without blocking
- Developers notified but not blocked

**Use Case:** Testing advisory-only mode.

---

## Integration Edge Cases

### 1. No SAST Findings, Only SCA Findings

**Scenario:**
- SAST phase: 0 findings (code is clean)
- SCA phase: 5 vulnerable dependencies detected
- 3 are reachable, 2 are not reachable

**Expected Behavior:**
- PR status depends on `fail_on_severity` config
- Comment includes SCA findings section
- No SAST findings shown
- Clear separation of findings by type
- Actionable remediation advice (upgrade/remove packages)

---

### 2. SCA Findings Suppressed by Confidence Threshold

**Scenario:**
- SCA finds 5 vulnerabilities
- LLM reachability phase evaluates:
  - 2 marked FOUND_IN_SOURCE (40-60% confidence)
  - 3 marked NOT_FOUND_IN_SOURCE (10-30% confidence)
- Threshold set to `sca_reachability_confidence_threshold: 0.5`

**Expected Behavior:**
- Only 2 HIGH-confidence findings included
- 3 LOW-confidence findings suppressed
- Comment explains filtering
- Developers can review suppressed findings if needed
- Reduces noise while catching likely issues

---

### 3. Large Number of Findings (100+)

**Scenario:**
- Massive lockfile (3000+ packages)
- OSV returns 150+ vulnerabilities
- LLM must analyze all for reachability
- Comment must summarize findings

**Expected Behavior:**
- Processing completes within timeout
- Comment is truncated/summarized (max 65k chars)
- Links to full report provided
- Findings grouped by severity
- No data loss (all findings in action check details)
- Performance acceptable

**Configuration:** May need:
- `osv_findings_max_in_comment: 50`
- `osv_summary_max_length: 300`

---

### 4. Comment Posting Failures

**Scenario:**
- PR analysis complete
- Finding: 5 vulnerabilities to report
- GitHub API call to post comment fails:
  - Network timeout
  - Rate limiting (429)
  - Authentication error (401)
  - Repo permission denied (403)

**Expected Behavior:**
- Retry logic with exponential backoff
- Fail gracefully if retry exhausted
- Action workflow exits with clear error message
- Developers notified (workflow failure)
- PR status: `action required` (not `passed`)
- Findings still available in action run details

---

## Test Scenarios Summary

| Edge Case | Fixture | Phase Affected | Critical? |
|-----------|---------|----------------|-----------|
| Empty lockfile | empty-lockfile.json | Phase 1 | Medium |
| Massive lockfile | massive-lockfile.json | Phase 1 | High |
| Malformed JSON | malformed-lockfile.json | Phase 1 | High |
| Duplicate packages | duplicate-packages-lockfile.json | Phase 1 | Low |
| Empty OSV response | osv-edge-cases.json | Phase 1 | Low |
| Oversized response | osv-edge-cases.json | Phase 1 | Medium |
| Missing fields | osv-edge-cases.json | Phase 1 | High |
| Invalid CVSS | osv-edge-cases.json | Phase 1 | Medium |
| Misaligned results | osv-edge-cases.json | Phase 1 | High |
| No imports | reachability-edge-cases.json | Phase 2 | Low |
| Dynamic imports | reachability-edge-cases.json | Phase 2 | High |
| Aliased imports | reachability-edge-cases.json | Phase 2 | Medium |
| Mixed severity | reachability-edge-cases.json | Phase 2 | Medium |
| Large diff | reachability-edge-cases.json | Phase 2 | High |
| Config: reachability=false | N/A | Phase 2 | Low |
| Config: reachability_threshold | N/A | Phase 2 | Low |
| Comment posting failures | N/A | Post-phase | High |

---

## Implementation Checklist

When implementing edge case handling, verify:

- [ ] **Lockfile Parsing:**
  - [ ] Empty dependencies handled
  - [ ] Large package counts capped
  - [ ] Invalid JSON caught and logged
  - [ ] Duplicates deduplicated
  - [ ] Null/missing fields have defaults

- [ ] **OSV Response Handling:**
  - [ ] Empty results list handled
  - [ ] Long summaries truncated
  - [ ] Null fields filled with defaults
  - [ ] Invalid CVSS ignored gracefully
  - [ ] Result misalignment detected and corrected
  - [ ] Duplicate CVEs deduplicated

- [ ] **Reachability Analysis:**
  - [ ] No-import diffs skip Phase 2
  - [ ] Dynamic imports marked UNCERTAIN
  - [ ] Aliased imports resolved correctly
  - [ ] Severity filtering applied
  - [ ] Large diffs handled within limits
  - [ ] Non-source files ignored

- [ ] **Configuration:**
  - [ ] Phase 2 can be disabled
  - [ ] Thresholds enforced correctly
  - [ ] Confidence filtering applied
  - [ ] Severity-based blocking configurable

- [ ] **Integration:**
  - [ ] Comment truncation at limits
  - [ ] Retry logic for API failures
  - [ ] Clear error messages
  - [ ] Graceful degradation
  - [ ] Performance within timeouts

---

## Performance Benchmarks

Target performance for edge cases:

- Empty lockfile: < 1s
- Massive lockfile (500 packages): < 10s
- Malformed lockfile: < 2s (with error logging)
- Large diff (498KB): < 15s
- 150 vulnerabilities + Phase 2: < 30s
- Comment posting with retries: < 5s per attempt

---

## Future Considerations

1. **Caching Strategy:** Cache OSV responses to reduce API calls
2. **Rate Limiting:** Implement exponential backoff for OSV queries
3. **Batch Processing:** Query OSV in batches instead of individual packages
4. **Reachability ML:** Train model on real codebases for better confidence scores
5. **Custom Policies:** Allow org-specific threat models and thresholds
6. **Audit Trail:** Maintain history of findings and resolutions
