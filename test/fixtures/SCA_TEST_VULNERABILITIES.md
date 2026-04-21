# SCA Test: Real Vulnerabilities Across Ecosystems

This directory contains lockfiles with known vulnerable packages across multiple package ecosystems. These are used to validate that the SCA (Software Composition Analysis) pipeline correctly identifies and reports on vulnerable dependencies.

## Overview

This test suite validates the guppy-agent's ability to detect real CVEs and security vulnerabilities across different dependency management systems.

## Vulnerable Packages Included

### npm (package-lock.json)

1. **axios@0.21.0**
   - **CVE**: CVE-2021-3749
   - **Type**: Server-Side Request Forgery (SSRF)
   - **Severity**: High
   - **Details**: axios versions before 0.21.1 are vulnerable to SSRF attacks through the `httpAgent` and `httpsAgent` options.

2. **lodash@4.17.11**
   - **CVE**: CVE-2021-23337
   - **Type**: Prototype Pollution
   - **Severity**: High
   - **Details**: lodash versions before 4.17.21 are vulnerable to prototype pollution via the `toPath` function.

3. **express@4.16.2**
   - **CVE**: CVE-2022-24999
   - **Type**: Denial of Service (DoS)
   - **Severity**: High
   - **Details**: express versions using vulnerable qs parser (6.5.1) are susceptible to DoS through malformed query strings.

### Python (Pipfile.lock)

1. **requests@2.6.0**
   - **CVE**: CVE-2016-3739
   - **Type**: Partial match on SSL hostname verification
   - **Severity**: High
   - **Details**: requests versions before 2.6.1 don't properly verify SSL certificates with partial wildcard matching.

2. **flask@0.12.0**
   - **CVE**: CVE-2018-1000656
   - **Type**: Broken cryptographic implementation
   - **Severity**: High
   - **Details**: Flask versions before 1.0 with JSON encoder have issues with cryptographic operations.

### Go (go.sum)

1. **github.com/gin-gonic/gin@v1.6.3**
   - **Type**: Known Denial of Service vulnerability
   - **Severity**: Medium
   - **Details**: Early versions of gin-gonic/gin had DoS vulnerabilities in request handling.

### Rust (Cargo.lock)

1. **serde@0.8.0**
   - **Type**: Arbitrary Code Execution
   - **Severity**: Critical
   - **Details**: Very old versions of serde had unsafe deserialization patterns.

### Ruby (Gemfile.lock)

1. **rails@5.0.0**
   - **CVE**: CVE-2016-6316
   - **Type**: CSS injection in rails-html-sanitizer
   - **Severity**: Medium
   - **Details**: Rails 5.0.0 with vulnerable sanitizer can be bypassed via CSS injection.

## Testing Instructions

1. **Run OSV Scanner** against these lockfiles:
   ```bash
   osv-scanner --lockfile=test/fixtures/package-lock.json
   osv-scanner --lockfile=test/fixtures/Pipfile.lock
   osv-scanner --lockfile=test/fixtures/go.sum
   osv-scanner --lockfile=test/fixtures/Cargo.lock
   osv-scanner --lockfile=test/fixtures/Gemfile.lock
   ```

2. **Expected Results**: OSV Scanner should report vulnerabilities for all packages listed above.

3. **Integration Test**: The guppy-agent should:
   - Successfully parse all lockfile formats
   - Detect the vulnerable versions
   - Generate accurate reports for each ecosystem
   - Include CVE details and severity ratings in reports

## Lockfile Formats

Each lockfile is formatted to match the standard syntax for its respective package manager:

- **npm**: Standard npm v2+ lockfile format with dependency trees
- **Python**: Pipenv lockfile format with hashes and metadata
- **Go**: go.mod/go.sum format with module paths and checksums
- **Rust**: Cargo.lock format with package entries and metadata
- **Ruby**: Bundler Gemfile.lock format with versioning

## Notes

- These are real, documented CVEs - not fabricated vulnerabilities
- Lockfiles are stripped of their own project dependencies and only contain the vulnerable packages
- This test helps validate the SCA pipeline's correctness before running on production codebases
- Each package version is intentionally outdated to ensure the vulnerabilities are detectable by current vulnerability databases

## References

- OSV.dev: https://osv.dev/
- NVD: https://nvd.nist.gov/
- GitHub Advisory Database: https://github.com/advisories
