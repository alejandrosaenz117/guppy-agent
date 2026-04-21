# SCA Performance Metrics & Benchmarks

## Test Scenarios Overview

This document tracks performance metrics across multiple SCA load scenarios to validate performance at scale (500 packages, near 500KB diff sizes, mixed ecosystems).

---

## Scenario 1: Large Lockfile (500 Packages)

### Configuration
- **Packages**: 500 (at cap limit)
- **Ecosystems**: npm (300), Python (100), Go (100)
- **Diff Size**: ~450KB (near 500KB limit)
- **Structure**: Realistic monorepo with nested dependencies

### Baseline Expectations
| Metric | Expected | Threshold | Notes |
|--------|----------|-----------|-------|
| Parse Time | <500ms | <1000ms | Lockfile parsing + dependency resolution |
| Memory Peak | <150MB | <300MB | Initial load + dependency graph |
| Dependencies Found | 500 | ±5% | Package count accuracy |
| Vulnerability Matches | 25-35 | +/-10% | Realistic CVE ratio for mixed ecosystem |
| Parse + Analysis | <2s | <5s | Total initial phase duration |

### Actual Results
| Run | Date | Parse Time | Memory Peak | Vulns Found | Parse+Analysis | Notes |
|-----|------|------------|-------------|-------------|-----------------|-------|
| 1 | TBD | | | | | |
| 2 | TBD | | | | | |
| 3 | TBD | | | | | |

---

## Scenario 2: LLM Performance (Phase 1 & 2)

### Phase 1: Full 500-Package Analysis

#### Configuration
- **Input**: 500 packages post-OSV triage
- **Task**: Generate reachability verdict for 500 packages
- **Model**: Claude Haiku 4.5 (optimized for cost at scale)
- **Batching**: Single phase with 500 package context

#### Baseline Expectations
| Metric | Expected | Threshold | Notes |
|--------|----------|-----------|-------|
| Total Tokens (Input) | 15,000-20,000 | <30,000 | 500 packages @ ~30-40 tokens each |
| Total Tokens (Output) | 8,000-12,000 | <20,000 | Verdicts + reasoning |
| Latency (P1) | 8-15s | <30s | Network + processing |
| Token Cost | $0.08-$0.12 | <$0.25 | At Haiku rates (~$0.80/$24 per 1M tokens) |
| Cache Hit (P2) | 80%+ | >70% | Prompt cache effectiveness |

#### Actual Results - Phase 1
| Run | Date | Input Tokens | Output Tokens | Latency | Cost | Cache Hit | Notes |
|-----|------|--------------|---------------|---------|------|-----------|-------|
| 1 | TBD | | | | | N/A | |
| 2 | TBD | | | | | N/A | |

### Phase 2: Candidate Chunking (20-Package Chunks)

#### Configuration
- **Input**: 500 packages split into 25 chunks of 20
- **Task**: Deep analysis per chunk with full code context
- **Batching**: Repeated calls with sliding context window

#### Baseline Expectations
| Metric | Expected | Threshold | Notes |
|--------|----------|-----------|-------|
| Tokens per Chunk | 6,000-8,000 | <12,000 | Reduced context vs Phase 1 |
| Chunks Processed | 25 | 25 | 500 ÷ 20 |
| Latency per Chunk | 3-5s | <10s | Smaller context = faster |
| Total Phase 2 Time | 75-125s | <300s | 25 × latency |
| Cumulative Token Cost | $0.30-$0.50 | <$1.00 | Phase 1 + Phase 2 |

#### Actual Results - Phase 2
| Chunk | Date | Tokens | Latency | Verdict Count | Notes |
|-------|------|--------|---------|---------------|-------|
| 1-5 | TBD | | | | |
| 6-10 | TBD | | | | |
| 11-15 | TBD | | | | |
| 16-20 | TBD | | | | |
| 21-25 | TBD | | | | |

---

## Scenario 3: OSV Batch Performance

### Configuration
- **Batch Size**: 500 packages
- **Chunk Size**: 100 packages per API call
- **Chunks**: 5 requests total
- **Rate Limiting**: Test resilience to 429 responses

### Baseline Expectations
| Metric | Expected | Threshold | Notes |
|--------|----------|-----------|-------|
| Chunk Request Count | 5 | 5 | 500 ÷ 100 |
| Response Time per Chunk | 300-600ms | <2000ms | API latency + parsing |
| Total OSV Time | 2-4s | <10s | Sequential chunk processing |
| Cache Hits | 30%+ | >20% | Dependency overlap = cache reuse |
| Rate Limit Retries | 0-2 | <5 | Resilience test |
| Total API Payloads | 500 | 500 | Package count consistency |

#### Chunking Strategy
```
Chunk 1:  [pkg-1...pkg-100]     (0-1s)
Chunk 2:  [pkg-101...pkg-200]   (1-2s)
Chunk 3:  [pkg-201...pkg-300]   (2-3s)
Chunk 4:  [pkg-301...pkg-400]   (3-4s)
Chunk 5:  [pkg-401...pkg-500]   (4-5s)
```

### Actual Results
| Chunk | Date | Request Time | Packages | Vulns Found | Retry Count | Notes |
|-------|------|--------------|----------|-------------|-------------|-------|
| 1 | TBD | | 100 | | | |
| 2 | TBD | | 100 | | | |
| 3 | TBD | | 100 | | | |
| 4 | TBD | | 100 | | | |
| 5 | TBD | | 100 | | | |
| Total | TBD | | 500 | | | |

---

## Scenario 4: Comment Posting Performance

### Configuration
- **Findings**: 100+ vulnerabilities to post as GitHub comments
- **Scenario A**: All findings are new (100 comments)
- **Scenario B**: 50 findings exist, 50 updates (deduplication)
- **Scenario C**: Batch retry with 10% failure rate

### Baseline Expectations
| Metric | Scenario A | Scenario B | Scenario C | Threshold |
|--------|-----------|-----------|-----------|-----------|
| New Comments Posted | 100 | 50 | ~90 | >85% |
| Existing Updates | 0 | 50 | ~45 | >80% |
| Dedup Accuracy | 100% | 100% | 95%+ | >90% |
| Total Time | 15-25s | 12-20s | 20-35s | <60s |
| API Calls | ~100 | ~100 | ~120 | <150 |
| Rate Limit Hits | 0 | 0 | 5-10 | <15 |

### Actual Results - Comment Posting
| Run | Date | Scenario | New Comments | Updates | Dedups | Total Time | API Calls | Notes |
|-----|------|----------|--------------|---------|--------|------------|-----------|-------|
| 1 | TBD | A | | | 100% | | | |
| 2 | TBD | B | | | 100% | | | |
| 3 | TBD | C | | | 95%+ | | | |

---

## Scenario 5: Memory & Token Budget

### Configuration
- **Packages Analyzed**: 500
- **Estimated LLM Context**: 30-50KB (500 pkgs at ~60-100 bytes each)
- **Concurrent Operations**: Single-threaded sequential processing

### Baseline Expectations
| Metric | Expected | Threshold | Notes |
|--------|----------|-----------|-------|
| **LLM Token Usage** | | | |
| Phase 1 Input Tokens | 18,000 | <25,000 | 500 × ~36 tokens |
| Phase 2 Total Tokens | 150,000 | <200,000 | 25 chunks × ~6,000 tokens |
| Combined Token Cost | $0.38-$0.62 | <$1.00 | 168,000 tokens at Haiku rate |
| | | | |
| **Scrubber Redaction** | | | |
| Redaction Time (500 pkgs) | 200-400ms | <1000ms | Regex + file scan |
| Redacted Patterns | 15-25 | ±20% | Path/credential patterns |
| Performance Impact | <5% | <10% | Relative to parsing |
| | | | |
| **Enricher (CWE Lookups)** | | | |
| Lookup Count | 25-35 | ±10% | 1 per CVE |
| Cache Hits | 60%+ | >50% | CWE reuse across CVEs |
| Lookup Time | 100-200ms | <500ms | DB query + enrichment |
| | | | |
| **Total Memory (Peak)** | | | |
| Baseline | ~50MB | <100MB | Node.js runtime |
| + Lockfile Parse | +80MB | <200MB | Dependency graph |
| + LLM Context | +20MB | <250MB | Token encoding |
| Final Peak | <150MB | <300MB | Safe threshold |

### Actual Results - Memory & Budget
| Metric | Phase | Actual | Expected | Status |
|--------|-------|--------|----------|--------|
| Token Usage (Phase 1) | LLM | | 18,000 | |
| Token Usage (Phase 2) | LLM | | 150,000 | |
| Scrubber Time | Redaction | | <400ms | |
| CWE Lookup Count | Enricher | | 30 | |
| CWE Cache Hit Rate | Enricher | | 60%+ | |
| Peak Memory | Runtime | | <150MB | |

---

## Performance Regression Detection

### Key Metrics to Watch
```javascript
{
  "parseTime": { "p50": 300, "p99": 600, "max": 1000 },
  "memoryPeak": { "baseline": 80, "threshold": 150, "unit": "MB" },
  "osvChunkTime": { "p50": 400, "p99": 800, "max": 2000, "unit": "ms" },
  "llmTokens": { "phase1": 18000, "phase2": 150000, "total": 168000 },
  "commentPostTime": { "p50": 200, "p99": 500, "max": 1000, "unit": "ms per comment" },
  "endToEndTime": { "expected": "20-30s", "threshold": "< 60s", "unit": "seconds" }
}
```

### Regression Thresholds
- **Parse Time**: >1s = investigate
- **Memory Peak**: >250MB = optimize
- **OSV Chunk Time**: >2.5s = check rate limiting
- **LLM Phase 1**: >30s = reduce context or batch
- **Comment Posting**: >1.5s per comment = check GitHub rate limits
- **End-to-End**: >120s = profile bottleneck

---

## Notes

1. **Ecosystem Mix**: npm (60%), Python (20%), Go (20%) reflects typical monorepo patterns
2. **Rate Limiting**: OSV API allows ~10 req/s; test with deliberate backoff
3. **LLM Caching**: Phase 2 should see 70%+ cache hits via prompt caching
4. **Comment Dedup**: Use finding hash to detect and update vs. new posts
5. **Memory Safety**: Monitor GC; >300MB = revisit batching strategy
6. **Token Cost**: Optimize chunking if Phase 2 tokens exceed 200,000 total
