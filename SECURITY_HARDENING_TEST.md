# Security Hardening Test Vector

This PR tests the injection hardening mitigations for `fix_snippet` and `fixed_version` fields.

## Test Vectors

### 1. Message Injection (Markdown in LLM message field)
The following SQL injection code will be flagged by Guppy:

```sql
-- Test: Message field should escape ** bold ** markdown
SELECT * FROM users WHERE id = '1' OR '1'='1'
```

**Expected:** The message field in the PR comment should escape any markdown characters.

### 2. Fix Injection (Markdown in LLM fix field)
Vulnerable code with a "fix" that contains markdown:

```python
# This is a fix: use **parameterized** queries with `execute` method
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Expected:** The fix field should escape `**bold**` and backticks.

### 3. Fence Breakout (Backticks in code snippet)
Code with embedded fence sequences:

```javascript
// Code with backticks that could break markdown fence
const fence = "\`\`\`";
const payload = "```\neval(malicious)";
```

**Expected:** The fence length should be calculated to prevent escape (4+ backticks for closing a 3-backtick embedded sequence).

### 4. Malformed Version (SCA)
An OSV response with malformed version should fall back to generic message.

**Expected:** If `fixed_version` doesn't match `/^\d+\.\d+\.\d+/`, fall back to "Update to a patched version" message.

## What to Verify in PR Comments

1. ✅ Message contains escaped markdown (no bold/italic rendering)
2. ✅ Fix field contains escaped backticks and markdown
3. ✅ Code fence is properly closed despite embedded backticks
4. ✅ Version numbers are specific (e.g., "4.17.21") and validated

## Related Commits

- `67a421e` — security: harden injection mitigations
- Previous commits adding remediation guidance
