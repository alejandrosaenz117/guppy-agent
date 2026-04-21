# SCA Performance Test Plan

## Overview

This document outlines the procedure for validating SCA (Supply Chain Analyzer) performance at scale. Tests cover five key scenarios: lockfile parsing, LLM analysis, OSV batching, comment posting, and memory/token budgets.

**Target Constraints:**
- Max 500 packages per run
- Max 500KB diff size
- Mixed ecosystem support (npm, Python, Go)
- <60s end-to-end latency
- <300MB peak memory
- <$1.00 total LLM cost per run

---

## Test Setup

### Prerequisites
1. Guppy Agent repository cloned locally
2. Node.js 18+ installed
3. GitHub token configured (for comment posting tests)
4. Sufficient API quota for OSV and LLM services

### Environment Configuration
```bash
# Set test environment variables
export GUPPY_PERF_TEST=true
export GUPPY_LOG_LEVEL=debug
export NODE_ENV=test

# Optional: Enable profiling
export NODE_OPTIONS="--inspect"
```

### Test Fixtures
- **Lockfile**: `test/fixtures/monorepo-lockfile.json` (500 packages, mixed ecosystems)
- **Metrics Template**: `test/fixtures/perf-metrics.md` (baseline tracking)
- **Diff Scenarios**: See "Test Scenarios" section below

---

## Test Scenarios

### Scenario 1: Lockfile Parsing & Dependency Resolution

**Objective:** Validate parsing performance on 500-package lockfile.

**Steps:**
1. Load `test/fixtures/monorepo-lockfile.json`
2. Parse dependencies recursively
3. Build complete dependency graph
4. Measure parse time, memory usage, package count
5. Verify ecosystem detection (npm/Python/Go)

**Expected Output:**
```javascript
{
  "parseTime": 250,           // milliseconds
  "memoryPeak": 85,           // MB
  "packagesFound": 500,
  "ecosystems": {
    "npm": 300,
    "python": 100,
    "go": 100
  },
  "resolvedDependencies": 500
}
```

**Acceptance Criteria:**
- [ ] Parse time <500ms
- [ ] Memory peak <150MB
- [ ] All 500 packages resolved
- [ ] Ecosystem counts accurate

**Test Command:**
```bash
npm run test:perf:parse -- --fixture monorepo-lockfile.json
```

---

### Scenario 2: LLM Performance - Phase 1 (Full Analysis)

**Objective:** Validate LLM capability to analyze 500 packages in single pass.

**Steps:**
1. Run Phase 1 LLM analysis on 500 packages
2. Capture input tokens, output tokens, latency
3. Log reachability verdicts for sample packages
4. Calculate token cost at Haiku rates
5. Verify cache efficiency baseline

**Expected Output:**
```javascript
{
  "phase": 1,
  "packagesAnalyzed": 500,
  "inputTokens": 18000,       // ~36 tokens per package
  "outputTokens": 10000,      // Verdicts + reasoning
  "latency": 12000,           // milliseconds
  "verdicts": {
    "REACHABLE": 45,
    "UNREACHABLE": 380,
    "UNCERTAIN": 75
  },
  "tokenCost": 0.11,          // USD
  "cacheHitRate": 0           // No cache on first run
}
```

**Acceptance Criteria:**
- [ ] Input tokens <25,000
- [ ] Output tokens <20,000
- [ ] Latency <30s
- [ ] Verdicts cover all 500 packages
- [ ] Token cost <$0.25

**Test Command:**
```bash
npm run test:perf:llm -- --phase 1 --packages 500
```

---

### Scenario 2b: LLM Performance - Phase 2 (Chunked Analysis)

**Objective:** Validate LLM performance with chunked (20-package) analysis and cache reuse.

**Steps:**
1. Immediately follow Phase 1 test (cache should be warm)
2. Run Phase 2 LLM analysis: 25 chunks × 20 packages
3. Log token usage per chunk
4. Measure prompt cache hit rate
5. Aggregate total Phase 2 cost
6. Verify chunk boundary handling (no duplicates)

**Expected Output:**
```javascript
{
  "phase": 2,
  "totalPackages": 500,
  "chunkSize": 20,
  "chunkCount": 25,
  "chunksProcessed": [
    { "chunk": 1, "packages": 20, "tokens": 7500, "cacheHit": true, "latency": 4200 },
    { "chunk": 2, "packages": 20, "tokens": 6800, "cacheHit": true, "latency": 3800 },
    // ... chunks 3-25
  ],
  "totalTokens": 175000,
  "totalCost": 0.42,
  "avgCacheHitRate": 0.82,
  "totalPhase2Latency": 105000    // milliseconds
}
```

**Acceptance Criteria:**
- [ ] 25 chunks processed successfully
- [ ] Tokens per chunk <12,000
- [ ] Cache hit rate >70%
- [ ] Total Phase 2 time <300s (goal: <180s)
- [ ] Cumulative cost (Phase 1 + 2) <$1.00

**Test Command:**
```bash
npm run test:perf:llm -- --phase 2 --packages 500 --chunk-size 20
```

---

### Scenario 3: OSV Batch Processing & Chunking

**Objective:** Validate OSV API performance with 500-package batches split into 100-package chunks.

**Steps:**
1. Prepare 500 packages from Scenario 1
2. Split into 5 chunks of 100 packages
3. Submit sequential OSV queries
4. Measure per-chunk latency, vulnerability counts
5. Track API rate-limit responses (429s)
6. Implement exponential backoff retry
7. Verify deduplication across chunks

**Expected Output:**
```javascript
{
  "totalPackages": 500,
  "chunkSize": 100,
  "chunkCount": 5,
  "results": [
    {
      "chunk": 1,
      "packages": 100,
      "vulnsFound": 8,
      "latency": 450,
      "statusCode": 200,
      "cached": false
    },
    {
      "chunk": 2,
      "packages": 100,
      "vulnsFound": 6,
      "latency": 520,
      "statusCode": 200,
      "cached": true
    },
    // ... chunks 3-5
  ],
  "totalVulns": 32,
  "totalLatency": 2650,
  "rateLimitRetries": 1,
  "cacheHitRate": 0.35,
  "deduplicationRate": 0.94
}
```

**Acceptance Criteria:**
- [ ] All 5 chunks complete successfully
- [ ] Per-chunk latency <2s (goal: <600ms)
- [ ] Total latency <10s
- [ ] Vulnerability count 25-35 (realistic ratio)
- [ ] Rate limit retries <5
- [ ] Deduplication >90% accuracy

**Test Command:**
```bash
npm run test:perf:osv -- --packages 500 --chunk-size 100
```

---

### Scenario 4: Comment Posting Performance

**Objective:** Validate GitHub comment posting at scale with deduplication.

**Steps:**

#### 4A: All New Comments (100 findings)
1. Generate 100 unique vulnerability findings
2. Post each as new GitHub comment
3. Measure API latency per comment
4. Verify comment formatting
5. Track total time

#### 4B: Mixed (50 new + 50 updates)
1. Pre-populate 50 comments in test PR
2. Generate 50 identical findings (should update)
3. Generate 50 new findings (should post)
4. Verify deduplication correctness
5. Track new vs. update ratio

#### 4C: Batch Retry (90 posts with 10% failure)
1. Inject 10% GitHub API failures
2. Implement exponential backoff
3. Verify successful retry on 9/10 items
4. Measure retry latency overhead

**Expected Output:**
```javascript
{
  "scenario": "4A",
  "totalFindings": 100,
  "newComments": 100,
  "updates": 0,
  "dedupsTriggered": 0,
  "avgLatencyPerComment": 210,     // milliseconds
  "totalTime": 23000,               // milliseconds
  "apiCallsTotal": 105,             // Includes retries
  "rateLimitHits": 0,
  "successRate": 1.0
}
```

**Acceptance Criteria - Scenario 4A:**
- [ ] 100 comments posted
- [ ] Avg latency per comment <300ms
- [ ] Total time <60s
- [ ] 0 rate limit hits (goal)
- [ ] 100% success rate

**Acceptance Criteria - Scenario 4B:**
- [ ] 50 new comments posted
- [ ] 50 updates applied (not new posts)
- [ ] Dedup accuracy 100%
- [ ] Total time <45s

**Acceptance Criteria - Scenario 4C:**
- [ ] >85 of 100 comments successful (retry success >85%)
- [ ] 10-15 API calls per failed item (exponential backoff)
- [ ] No more than 2 retry rounds per item

**Test Command:**
```bash
npm run test:perf:comments -- --scenario 4A --findings 100
npm run test:perf:comments -- --scenario 4B --findings 100
npm run test:perf:comments -- --scenario 4C --findings 100 --failure-rate 0.1
```

---

### Scenario 5: Memory & Token Budget

**Objective:** Validate memory usage and LLM token budget across full pipeline.

**Steps:**
1. Run full pipeline: parse → OSV → LLM → comment
2. Monitor memory at each stage
3. Aggregate token usage (Phase 1 + 2)
4. Measure scrubber redaction time
5. Count CWE enricher lookups
6. Track cache efficiency

**Expected Output:**
```javascript
{
  "memory": {
    "baseline": 50,                 // MB - Node.js startup
    "afterParse": 130,              // +80MB for dep graph
    "afterOsv": 135,                // +5MB for results
    "afterLlm": 155,                // +20MB for context
    "peak": 155,
    "threshold": 300                // Safe limit
  },
  "tokens": {
    "phase1": {
      "input": 18000,
      "output": 10000,
      "total": 28000
    },
    "phase2": {
      "input": 155000,
      "output": 20000,
      "total": 175000
    },
    "combined": 203000,
    "estimatedCost": 0.53           // USD
  },
  "scrubber": {
    "duration": 320,                // milliseconds
    "patternsMatched": 18,
    "pathsRedacted": 145,
    "credentialsRedacted": 3
  },
  "enricher": {
    "cweLookupsInitiated": 32,
    "cweLookupsFromCache": 19,
    "cacheHitRate": 0.59,
    "totalLookupTime": 145          // milliseconds
  }
}
```

**Acceptance Criteria - Memory:**
- [ ] Peak memory <300MB
- [ ] Post-parse memory <200MB
- [ ] GC effective (no >1s pauses)

**Acceptance Criteria - Tokens:**
- [ ] Phase 1 <25,000 tokens
- [ ] Phase 2 <200,000 tokens
- [ ] Combined cost <$1.00

**Acceptance Criteria - Scrubber:**
- [ ] Redaction time <1s
- [ ] All credential patterns detected
- [ ] Performance impact <10%

**Acceptance Criteria - Enricher:**
- [ ] Cache hit rate >50%
- [ ] Lookup time <500ms
- [ ] No missing CWE enrichments

**Test Command:**
```bash
npm run test:perf:budget -- --full-pipeline
```

---

## Running Tests

### Individual Tests
```bash
# Scenario 1: Parsing
npm run test:perf:parse

# Scenario 2: LLM (Phase 1 & 2)
npm run test:perf:llm

# Scenario 3: OSV Batching
npm run test:perf:osv

# Scenario 4: Comments
npm run test:perf:comments

# Scenario 5: Budget
npm run test:perf:budget
```

### Full Test Suite
```bash
npm run test:perf
```

### With Profiling
```bash
node --prof --inspect test/perf/run-all-scenarios.js
```

---

## Result Interpretation

### Pass Criteria
- All Acceptance Criteria met for each scenario
- No regressions vs. baseline metrics
- End-to-end latency <60s
- Memory peak <300MB
- LLM cost <$1.00

### Warning Signs
| Metric | Baseline | Warning | Critical |
|--------|----------|---------|----------|
| Parse Time | 300ms | >600ms | >1s |
| Memory Peak | 150MB | >200MB | >300MB |
| OSV Chunk Time | 500ms | >1s | >2.5s |
| LLM Phase 1 | 12s | >20s | >30s |
| Comment Posting | 200ms/ea | >400ms/ea | >1s/ea |
| E2E Time | 25s | >45s | >60s |

### Regression Actions
1. **Parse Time Increased:** Profile dependency resolution, check for circular dependencies
2. **Memory Spike:** Check for memory leaks in GC, reduce batch sizes
3. **OSV Latency:** Verify API health, check rate limiting, inspect network
4. **LLM Cost Overrun:** Review tokenization, consider smaller chunks or model optimization
5. **Comment Posting Slow:** Check GitHub API rate limits, inspect retry logic

---

## Continuous Monitoring

### Metrics to Track
1. **Parse Performance:** Over commits
2. **LLM Token Usage:** Monitor for prompt engineering changes
3. **OSV Efficiency:** Track cache hit rates, API changes
4. **Comment Posting:** Validate dedup logic doesn't break
5. **Memory Trends:** Watch for gradual leaks

### Alerting
- Parse time regression >25% → investigate
- Memory peak >250MB → profile and optimize
- Token cost increase >20% → review LLM strategy
- Comment posting errors >5% → check GitHub status

---

## Appendix: Fixture Details

### monorepo-lockfile.json
- **Total Packages:** 500
- **npm Packages:** 300 (typical web stack)
- **Python Packages:** 100 (data science + backend)
- **Go Packages:** 100 (infrastructure + services)
- **File Size:** ~450KB (near limit)
- **Nested Dependencies:** Realistic depth (5-10 levels)

### Test Diff Scenarios
1. **Small (~50KB):** 50-package lockfile update
2. **Medium (~200KB):** 250-package lockfile update
3. **Large (~450KB):** Full 500-package lockfile update
4. **Mixed Ecosystem (~400KB):** npm + Python + Go
5. **Monorepo (~480KB):** Nested workspaces + complex deps

---

## Notes

1. **Rate Limiting:** OSV API allows ~10 req/s globally; tests use exponential backoff
2. **LLM Caching:** Prompt cache TTL = 5 minutes; Phase 2 should run immediately after Phase 1
3. **GitHub API:** Standard rate limits (60/min unauthenticated, 5000/min authenticated)
4. **Cost Tracking:** All LLM calls logged with token counts for cost analysis
5. **Reproducibility:** All tests use fixed seeds for RNG; fixtures are version-controlled
6. **CI/CD:** Perf tests run on dedicated hardware (consistent baseline)

---

## Sign-Off

- **Test Plan Version:** 1.0
- **Last Updated:** April 2026
- **Owner:** SCA Performance Team
- **Review Cycle:** Quarterly (or on major refactors)
