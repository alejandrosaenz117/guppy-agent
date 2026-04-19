# GUPPI — General Unit Primary Peripheral Interface

> _Deployed as `guppy-agent` for GitHub Actions._

![guppy-agent banner](guppy-agent-banner.png)

> _"It's a trap!"_ — Guppy, every time your PR has an SQL injection

AI-powered security scanner for pull requests. Scans diffs, posts inline comments, blocks merges. Named after the ship AI from the Bobiverse — lore-accurate because Bob would absolutely automate this, and Guppy would absolutely be paranoid about it.

## Usage

```yaml
- uses: alejandrosaenz117/guppy-agent@v1
  with:
    api_key: ${{ secrets.LLM_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input                | Default                      | Description                                     |
| -------------------- | ---------------------------- | ----------------------------------------------- |
| `api_key`            | required                     | Anthropic, OpenAI, or Google API key            |
| `github_token`       | required                     | `${{ secrets.GITHUB_TOKEN }}` works             |
| `provider`           | `anthropic`                  | `anthropic` · `openai` · `google`               |
| `model`              | `claude-3-5-sonnet-20241022` | Any model from the provider                     |
| `fail_on_severity`   | `high`                       | `critical` · `high` · `medium` · `low` · `none` |
| `post_comments`      | `true`                       | Post inline PR comments for each finding. Ignored when `upload_sarif` is `true`.  |
| `upload_sarif`       | `false`                      | Upload findings to GitHub Advanced Security. Requires GHAS license.              |
| `structural_analysis` | `false`                     | Run [chiasmus](https://github.com/yogthos/chiasmus) call graph analysis on diff files. Enriches Hunter context and pre-filters unreachable findings. |

## How it works

Guppy runs two LLM passes. The Hunter finds everything. The Skeptic tells the Hunter it's being paranoid. Only real vulnerabilities survive. If one is critical, Guppy says _"It's a trap!"_ and fails the build.

Diffs are scrubbed for secrets using [@secretlint/secretlint-rule-preset-recommend](https://github.com/secretlint/secretlint) before transmission. Guppy does not trust the diff. Guppy does not trust anything.

When `structural_analysis: true`, Guppy adds [chiasmus](https://github.com/yogthos/chiasmus) structural analysis: the Hunter gets enriched context from call graphs, and unreachable findings are pre-filtered before the Skeptic pass, reducing false positives and improving token efficiency.

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
