# GUPPI — General Unit Primary Peripheral Interface

> _Deployed as `guppy-agent` for GitHub Actions._

![guppy-agent banner](guppy-agent-banner.png)

> _"It's a trap!"_ — Guppy, every time your PR has a critical vulnerability

AI-powered security scanner for pull requests. Scans diffs, posts inline comments, blocks merges. Named after the ship AI from the Bobiverse — lore-accurate because Bob would absolutely automate this, and Guppy would absolutely be paranoid about it.

## Usage

```yaml
- uses: alejandrosaenz117/guppy-agent@v1
  env:
    LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Passing secrets via `env:` instead of `with:` is the recommended pattern — it avoids exposing secrets as action input parameters, which can appear in workflow logs and metadata.

Both `LLM_API_KEY` and `GITHUB_TOKEN` also accept the legacy `with:` input parameters (`api_key` and `github_token`) for backward compatibility.

## Inputs

| Input                | Default                      | Description                                     |
| -------------------- | ---------------------------- | ----------------------------------------------- |
| `api_key`            | —                            | Anthropic, OpenAI, or Google API key. Prefer `LLM_API_KEY` env var. |
| `github_token`       | —                            | GitHub token. Prefer `GITHUB_TOKEN` env var (set automatically by the runner). |
| `provider`           | `anthropic`                  | `anthropic` · `openai` · `google`               |
| `model`              | `claude-3-5-sonnet-20241022` | Any model from the provider                     |
| `fail_on_severity`   | `high`                       | `critical` · `high` · `medium` · `low` · `none` |
| `comment_severity_threshold` | `high` | Minimum severity for posting PR comments (`critical` · `high` · `medium` · `low` · `none`) |
| `skeptic_pass`       | `true`                       | Run a second pass to filter false positives. Set to `false` for single-pass mode. |
| `post_comments`      | `true`                       | Post inline PR comments for each finding. Ignored when `upload_sarif` is `true`.  |
| `upload_sarif`       | `false`                      | Upload findings to GitHub Advanced Security. Requires GHAS license.              |
| `sca_enabled`        | `true`                       | Enable SCA scanning                                                              |
| `sca_scanner`        | `osv`                        | Scanner to use (`osv`)                                                           |
| `sca_reachability`   | `true`                       | Enable LLM reachability analysis                                                 |
| `sca_reachability_threshold` | `high`              | Minimum severity for call-site analysis                                          |
| `sca_reachability_confidence_threshold` | `2`       | Minimum confidence to block build (1–3)                                          |

## SCA Outputs

| Output | Description |
|--------|-------------|
| `sca_findings_count` | Total SCA vulnerabilities found |
| `sca_blocking_count` | SCA findings that block the build |

## SCA (Software Composition Analysis)

Guppy automatically scans dependency lockfiles changed in your PR diff for known vulnerabilities using the [OSV public API](https://osv.dev) — no API key required. SCA runs in parallel with SAST analysis.

### Supported Ecosystems

SCA auto-detects the ecosystem from the lockfile filename:

| Lockfile | Ecosystem |
|----------|-----------|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | npm |
| `Pipfile.lock`, `poetry.lock` | PyPI |
| `go.sum` | Go |
| `Cargo.lock` | Cargo (Rust) |
| `Gemfile.lock` | RubyGems |

For the full list of OSV-supported ecosystems, see the [OSV ecosystem documentation](https://osv.dev/docs/#section/OSV-API/Ecosystems).

### Reachability Analysis

When a vulnerable package is found, Guppy runs an LLM-powered reachability analysis to determine whether the vulnerable code is actually called:

- **REACHABLE** — the vulnerable function is called in the diff
- **UNCERTAIN** — the package is imported but the specific vulnerable function is not clearly visible
- **NOT_REACHABLE** — the package is not imported in the diff

Each verdict includes a confidence score (1–3):
- **3 — Confirmed:** Direct evidence of the vulnerable call site
- **2 — Possible:** Package is used, evidence is suggestive
- **1 — Unlikely:** Minimal evidence, manual review recommended

Findings only block the build if `reachability_confidence >= sca_reachability_confidence_threshold` (default: 2).

## How it works

Guppy runs two LLM passes. The Hunter finds everything. The Skeptic tells the Hunter it's being paranoid. Only real vulnerabilities survive. If one is critical, Guppy says _"It's a trap!"_ and fails the build.

Diffs are scrubbed for secrets using [@secretlint/secretlint-rule-preset-recommend](https://github.com/secretlint/secretlint) before transmission. Guppy does not trust the diff. Guppy does not trust anything.

## CWE + CAPEC enrichment

Every finding is enriched with data from the [MITRE CWE database](https://cwe.mitre.org) via [fetch-cwe-list](https://github.com/alejandrosaenz117/fetch-cwe-list). Each inline PR comment includes:

- **CWE ID + description** — the official weakness classification
- **CAPEC attack patterns** — how an attacker would actually exploit it, with links
- **Known CVEs** — real-world examples of the vulnerability in the wild

During analysis, Guppy has access to three on-demand CWE lookup tools: find_cwe_by_id, find_cwe_by_name, and find_cwe_by_capec. The Hunter uses these tools to enrich findings with official CWE data instead of hallucinating IDs.

## What Guppy detects

Beyond the classics (SQLi, XSS, command injection), Guppy's Hunter prompt covers:

- **Supply chain** — typosquatted packages, unpinned dependencies, suspicious postinstall scripts
- **AI & agentic security** — prompt injection, LLM output used without validation, excessive agent permissions, MCP trust boundary violations
- **Auth & crypto** — weak algorithms (MD5/SHA1), hardcoded secrets, JWT misuse
- **Data & privacy** — PII/PAN in logs or responses, unsafe deserialization

## License

MIT
