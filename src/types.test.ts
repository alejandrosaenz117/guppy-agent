import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FindingSchema, FindingsSchema, ActionInputsSchema, SEVERITY_ORDER, REACHABILITY_CONFIDENCE_LABELS } from './types.js';

describe('FindingSchema', () => {
  const validFinding = {
    file: 'src/auth.ts',
    line: 42,
    severity: 'high',
    type: 'SQL Injection',
    message: 'User input concatenated directly into SQL query.',
    fix: 'Use parameterized queries.',
  };

  it('accepts a valid finding', () => {
    const result = FindingSchema.safeParse(validFinding);
    assert.ok(result.success);
  });

  it('accepts line number of 0 (bounds removed for Anthropic schema compatibility)', () => {
    const result = FindingSchema.safeParse({ ...validFinding, line: 0 });
    assert.ok(result.success);
  });

  it('accepts negative line numbers (bounds removed for Anthropic schema compatibility)', () => {
    const result = FindingSchema.safeParse({ ...validFinding, line: -1 });
    assert.ok(result.success);
  });

  it('rejects non-integer line numbers', () => {
    const result = FindingSchema.safeParse({ ...validFinding, line: 1.5 });
    assert.ok(!result.success);
  });

  it('accepts file paths with newlines (regex removed for Anthropic schema compatibility)', () => {
    const result = FindingSchema.safeParse({ ...validFinding, file: 'src/foo\nbar.ts' });
    assert.ok(result.success);
  });

  it('accepts file paths with null bytes (regex removed for Anthropic schema compatibility)', () => {
    const result = FindingSchema.safeParse({ ...validFinding, file: 'src/foo\0bar.ts' });
    assert.ok(result.success);
  });

  it('rejects file paths longer than 500 chars', () => {
    const result = FindingSchema.safeParse({ ...validFinding, file: 'a'.repeat(501) });
    assert.ok(!result.success);
  });

  it('rejects type longer than 200 chars', () => {
    const result = FindingSchema.safeParse({ ...validFinding, type: 'x'.repeat(201) });
    assert.ok(!result.success);
  });

  it('rejects message longer than 2000 chars', () => {
    const result = FindingSchema.safeParse({ ...validFinding, message: 'x'.repeat(2001) });
    assert.ok(!result.success);
  });

  it('rejects fix longer than 2000 chars', () => {
    const result = FindingSchema.safeParse({ ...validFinding, fix: 'x'.repeat(2001) });
    assert.ok(!result.success);
  });

  it('rejects invalid severity values', () => {
    const result = FindingSchema.safeParse({ ...validFinding, severity: 'urgent' });
    assert.ok(!result.success);
  });

  it('accepts all valid severity levels', () => {
    for (const severity of ['critical', 'high', 'medium', 'low', 'none']) {
      const result = FindingSchema.safeParse({ ...validFinding, severity });
      assert.ok(result.success, `severity '${severity}' should be valid`);
    }
  });

  it('accepts fix_snippet when present', () => {
    const result = FindingSchema.safeParse({
      file: 'src/auth.ts',
      line: 42,
      severity: 'high',
      type: 'SQL Injection',
      message: 'User input concatenated directly into SQL query.',
      fix: 'Use parameterized queries.',
      fix_snippet: 'const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
    });
    assert.ok(result.success);
  });

  it('accepts finding without fix_snippet (optional field)', () => {
    const result = FindingSchema.safeParse({
      file: 'src/auth.ts',
      line: 42,
      severity: 'high',
      type: 'SQL Injection',
      message: 'User input concatenated directly into SQL query.',
      fix: 'Use parameterized queries.',
    });
    assert.ok(result.success);
    assert.equal(result.data?.fix_snippet, undefined);
  });

  it('rejects fix_snippet longer than 3000 chars', () => {
    const result = FindingSchema.safeParse({
      file: 'src/auth.ts',
      line: 42,
      severity: 'high',
      type: 'SQL Injection',
      message: 'msg',
      fix: 'fix',
      fix_snippet: 'x'.repeat(3001),
    });
    assert.ok(!result.success);
  });
});

describe('FindingsSchema', () => {
  it('accepts empty findings object', () => {
    const result = FindingsSchema.safeParse({ findings: [] });
    assert.ok(result.success);
  });

  it('accepts an object with valid findings array', () => {
    const result = FindingsSchema.safeParse({
      findings: [
        { file: 'a.ts', line: 1, severity: 'high', type: 'XSS', message: 'msg', fix: 'fix' },
        { file: 'b.ts', line: 2, severity: 'low', type: 'Info', message: 'msg2', fix: 'fix2' },
      ],
    });
    assert.ok(result.success);
  });

  it('rejects if any finding is invalid', () => {
    const result = FindingsSchema.safeParse({
      findings: [
        { file: 'a.ts', line: 1, severity: 'high', type: 'XSS', message: 'msg', fix: 'fix' },
        { file: 'b.ts', line: 2, severity: 'invalid-severity', type: 'Info', message: 'msg2', fix: 'fix2' },
      ],
    });
    assert.ok(!result.success);
  });
});

describe('ActionInputsSchema', () => {
  const validInputs = {
    api_key: 'sk-ant-test123',
    provider: 'anthropic',
    model: 'claude-3-5-sonnet-20241022',
    post_comments: true,
    fail_on_severity: 'high',
    github_token: 'ghs_token123',
  };

  it('accepts valid inputs', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
  });

  it('defaults provider to anthropic when omitted', () => {
    const { provider, ...rest } = validInputs;
    const result = ActionInputsSchema.safeParse(rest);
    assert.ok(result.success);
    assert.equal(result.data?.provider, 'anthropic');
  });

  it('defaults fail_on_severity to high when omitted', () => {
    const { fail_on_severity, ...rest } = validInputs;
    const result = ActionInputsSchema.safeParse(rest);
    assert.ok(result.success);
    assert.equal(result.data?.fail_on_severity, 'high');
  });

  it('defaults post_comments to true when omitted', () => {
    const { post_comments, ...rest } = validInputs;
    const result = ActionInputsSchema.safeParse(rest);
    assert.ok(result.success);
    assert.equal(result.data?.post_comments, true);
  });

  it('rejects invalid provider', () => {
    const result = ActionInputsSchema.safeParse({ ...validInputs, provider: 'mistral' });
    assert.ok(!result.success);
  });

  it('accepts all valid providers', () => {
    for (const provider of ['anthropic', 'openai', 'google']) {
      const result = ActionInputsSchema.safeParse({ ...validInputs, provider });
      assert.ok(result.success, `provider '${provider}' should be valid`);
    }
  });

  it('rejects model names longer than 200 chars', () => {
    const result = ActionInputsSchema.safeParse({ ...validInputs, model: 'x'.repeat(201) });
    assert.ok(!result.success);
  });

  it('rejects missing api_key', () => {
    const { api_key, ...rest } = validInputs;
    const result = ActionInputsSchema.safeParse(rest);
    assert.ok(!result.success);
  });

  it('rejects missing github_token', () => {
    const { github_token, ...rest } = validInputs;
    const result = ActionInputsSchema.safeParse(rest);
    assert.ok(!result.success);
  });

  it('defaults upload_sarif to false when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.upload_sarif, false);
  });

  it('accepts upload_sarif true', () => {
    const result = ActionInputsSchema.safeParse({ ...validInputs, upload_sarif: true });
    assert.ok(result.success);
    assert.equal(result.data?.upload_sarif, true);
  });

});

describe('SEVERITY_ORDER', () => {
  it('orders critical above high', () => {
    assert.ok(SEVERITY_ORDER.critical > SEVERITY_ORDER.high);
  });

  it('orders high above medium', () => {
    assert.ok(SEVERITY_ORDER.high > SEVERITY_ORDER.medium);
  });

  it('orders medium above low', () => {
    assert.ok(SEVERITY_ORDER.medium > SEVERITY_ORDER.low);
  });

  it('orders low above none', () => {
    assert.ok(SEVERITY_ORDER.low > SEVERITY_ORDER.none);
  });

  it('none has value 0', () => {
    assert.equal(SEVERITY_ORDER.none, 0);
  });
});

describe('REACHABILITY_CONFIDENCE_LABELS', () => {
  it('should export REACHABILITY_CONFIDENCE_LABELS', () => {
    assert.ok(REACHABILITY_CONFIDENCE_LABELS);
  });

  it('should have labels for confidence levels 1, 2, and 3', () => {
    assert.ok(REACHABILITY_CONFIDENCE_LABELS[1]);
    assert.ok(REACHABILITY_CONFIDENCE_LABELS[2]);
    assert.ok(REACHABILITY_CONFIDENCE_LABELS[3]);
  });

  it('should have appropriate label strings', () => {
    assert.equal(typeof REACHABILITY_CONFIDENCE_LABELS[1], 'string');
    assert.equal(typeof REACHABILITY_CONFIDENCE_LABELS[2], 'string');
    assert.equal(typeof REACHABILITY_CONFIDENCE_LABELS[3], 'string');
  });
});

describe('ActionInputsSchema SCA fields', () => {
  const validInputs = {
    api_key: 'sk-ant-test123',
    provider: 'anthropic',
    model: 'claude-3-5-sonnet-20241022',
    post_comments: true,
    fail_on_severity: 'high',
    github_token: 'ghs_token123',
  };

  it('defaults sca_enabled to true when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.sca_enabled, true);
  });

  it('defaults sca_scanner to osv when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.sca_scanner, 'osv');
  });

  it('defaults sca_reachability to true when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.sca_reachability, true);
  });

  it('defaults sca_reachability_threshold to high when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.sca_reachability_threshold, 'high');
  });

  it('defaults sca_reachability_confidence_threshold to 2 when omitted', () => {
    const result = ActionInputsSchema.safeParse(validInputs);
    assert.ok(result.success);
    assert.equal(result.data?.sca_reachability_confidence_threshold, 2);
  });

  it('accepts valid sca_reachability_confidence_threshold values 1, 2, 3', () => {
    for (const threshold of [1, 2, 3]) {
      const result = ActionInputsSchema.safeParse({ ...validInputs, sca_reachability_confidence_threshold: threshold });
      assert.ok(result.success, `threshold '${threshold}' should be valid`);
    }
  });

  it('rejects invalid sca_reachability_confidence_threshold values', () => {
    const result = ActionInputsSchema.safeParse({ ...validInputs, sca_reachability_confidence_threshold: 4 });
    assert.ok(!result.success);
  });
});
