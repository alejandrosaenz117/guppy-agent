# Guppy Agent — Admiral Ackbar's Security Scanner for GitHub

> *It's a trap!* — Guppy, detecting CVEs like a pro.

## What is Guppy?

Guppy is a GitHub Action that brings Admiral Ackbar's paranoid security mindset to your pull requests. Named after the beloved GUP (General Utility Platform) of the Bobiverse, Guppy scans code diffs using Claude, GPT-4, or Gemini to identify vulnerabilities before they reach production.

### The Voice

Every log message is in Guppy's persona:
- **"Observation:"** Facts about the scan
- **"Calculation:"** Analysis and decisions
- **"Warning:"** Potential issues or blocks
- **"Information:"** Details and context
- **"It's a trap!"** When critical vulnerabilities are found

### Lore

Guppy operates under the "Bobiverse Protocol" — inspired by the *Bobiverse* series where Bob's ships are protected by paranoid AIs. Like Guppy (the GUP), this action watches for attacks from *The Others*, *Medeiros*, and the *Brazilian Empire* of bad code patterns.

If the scan detects no issues, Guppy reports: *"The tactical situation is clear. No traps detected, Bob."*

If the build is blocked by severity thresholds: *"I somehow manage to look disappointed, although if pressed, I couldn't for the life of me describe what a disappointed fish looked like."*

---

## Quick Start

### 1. Add to Your Workflow

```yaml
- name: Guppy Security Scan
  uses: yourusername/guppy-agent@main
  with:
    api_key: ${{ secrets.LLM_API_KEY }}
    provider: 'anthropic'  # or 'openai', 'google'
    github_token: ${{ secrets.GITHUB_TOKEN }}
    fail_on_severity: 'high'
    post_comments: true
```

### 2. Set Up Secrets

Add your LLM API key to GitHub Secrets:
- **For Anthropic:** `ANTHROPIC_API_KEY` (format: `sk-ant-...`)
- **For OpenAI:** `OPENAI_API_KEY` (format: `sk-...`)
- **For Google:** `GOOGLE_API_KEY`

---

## How to Get Guppy for Free

Guppy works with free tiers of major LLM providers:

### Claude (Anthropic) — Free Tier
- Sign up at https://console.anthropic.com
- Get **$5 free credits** (good for ~50-100 scans depending on diff size)
- No credit card required for free tier
- Use model: `claude-3-5-sonnet-20241022` or `claude-3-5-haiku-20241022` (cheaper)

### GPT-4o Mini (OpenAI) — Free Tier
- Sign up at https://platform.openai.com
- Get **$5 free credits**
- Use model: `gpt-4o-mini` (very affordable)

### Gemini 1.5 Pro (Google) — Free Tier
- Sign up at https://ai.google.dev
- Get **free daily quota** (60 RPM)
- Use model: `gemini-2.0-flash` (latest, fastest)

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_key` | ✅ Yes | — | LLM API key (Anthropic, OpenAI, or Google) |
| `provider` | ❌ No | `anthropic` | Which LLM: `anthropic`, `openai`, `google` |
| `model` | ❌ No | `claude-3-5-sonnet-20241022` | Specific model to use |
| `github_token` | ✅ Yes | — | GitHub token for PR interactions |
| `post_comments` | ❌ No | `true` | Post inline comments for each finding |
| `fail_on_severity` | ❌ No | `high` | Fail build if findings ≥ this level: `critical`, `high`, `medium`, `low`, `none` |

---

## Outputs

| Output | Description |
|--------|-------------|
| `findings_count` | Total vulnerabilities found |
| `blocking_count` | Vulnerabilities that meet fail threshold |

---

## The Bobiverse Protocol: Two-Pass Auditing

Guppy uses two AI passes to avoid false positives:

**Pass 1 — Hunter:** Identifies *every* potential security issue.
**Pass 2 — Skeptic:** Critically analyzes findings and filters false positives.

Only truly exploitable vulnerabilities block the build.

---

## OIDC Configuration (Advanced)

For enhanced security, use GitHub's Workload Identity instead of API tokens:

```yaml
permissions:
  id-token: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Get Workload Identity Token
        id: idtoken
        uses: actions/github-script@v7
        with:
          result-encoding: string
          script: |
            return await core.getIDToken('https://your-service.example.com');

      - name: Guppy Security Scan
        uses: yourusername/guppy-agent@main
        with:
          api_key: ${{ secrets.LLM_API_KEY }}
          github_token: ${{ steps.idtoken.outputs.result }}
```

This eliminates the need to store long-lived tokens.

---

## Examples

### Fail on Critical Only

```yaml
- name: Guppy (Strict Mode)
  uses: yourusername/guppy-agent@main
  with:
    api_key: ${{ secrets.LLM_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    fail_on_severity: 'critical'
```

### Use GPT-4 Turbo

```yaml
- name: Guppy (OpenAI)
  uses: yourusername/guppy-agent@main
  with:
    api_key: ${{ secrets.OPENAI_API_KEY }}
    provider: 'openai'
    model: 'gpt-4-turbo'
    github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Report Only, No Blocking

```yaml
- name: Guppy (Report Only)
  uses: yourusername/guppy-agent@main
  with:
    api_key: ${{ secrets.LLM_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    fail_on_severity: 'none'
```

---

## Behavior & Logging

Guppy logs all analysis to the GitHub Actions console in its distinctive voice:

```
[Guppy] Acknowledged. Initiating security scan. As you wish, Bob.
[Guppy] Analyzing PR #42...
[Guppy] Diff scrubbed. Proceeding to analysis...
[Guppy] Calculation: 3 potential vulnerabilities identified.
[Guppy] Posting inline comments to PR...
[Guppy] 3 comment(s) posted.
[Guppy] Calculation: Threat level exceeds safety parameters. Terminating build sequence, Bob.
```

---

## What Guppy Detects

- SQL injection, command injection, XSS
- Hardcoded secrets and API keys
- Insecure cryptography and weak algorithms
- Unsafe deserialization and XXE
- Missing input validation
- Authentication/authorization flaws
- Path traversal and SSRF
- Dependency vulnerabilities (if visible in imports)

---

## Privacy & Security

- **Diffs are scrubbed:** Guppy masks API keys, tokens, and passwords before sending to the LLM
- **No caching:** Diffs are not cached by default
- **Private LLM calls:** Use your own API key; no third-party analysis

---

## Troubleshooting

### "Not running in a PR context"
Guppy only works on pull requests. Check your workflow trigger:
```yaml
on:
  pull_request:
```

### "API key invalid"
Double-check your secret name and that it matches your provider.

### "Too many false positives"
The Skeptic pass filters most false positives, but complex code may trigger warnings. Lower `fail_on_severity` if needed.

---

## Contributing

Found a bug or want to improve Guppy? Contributions welcome!

---

## License

MIT

---

**Admiral Ackbar would be proud.** 6
