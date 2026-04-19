# guppy-agent

> *"It's a trap!"* — Guppy, every time your PR has an SQL injection

AI-powered security scanner for pull requests. Scans diffs, posts inline comments, blocks merges. Named after the ship AI from the Bobiverse — lore-accurate because Bob would absolutely automate this, and Guppy would absolutely be paranoid about it.

## Usage

```yaml
- uses: your-username/guppy-agent@main
  with:
    api_key: ${{ secrets.LLM_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `api_key` | required | Anthropic, OpenAI, or Google API key |
| `github_token` | required | `${{ secrets.GITHUB_TOKEN }}` works |
| `provider` | `anthropic` | `anthropic` · `openai` · `google` |
| `model` | `claude-3-5-sonnet-20241022` | Any model from the provider |
| `fail_on_severity` | `high` | `critical` · `high` · `medium` · `low` · `none` |
| `post_comments` | `true` | Post inline PR comments for each finding |

## How it works

Two LLM passes. The Hunter finds everything. The Skeptic tells the Hunter it's being paranoid. Only real vulnerabilities survive. If one is critical, Guppy says *"It's a trap!"* and fails the build.

Diffs are scrubbed for secrets before being sent to the LLM, because Guppy is not an idiot.

## License

MIT
