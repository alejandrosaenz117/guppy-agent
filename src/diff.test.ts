import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractTouchedLines, isStaleComment } from './diff.js';

// Minimal valid unified diff for a single file
function makeDiff(file: string, oldStart: number, newStart: number, lines: string[]): string {
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -${oldStart},${lines.filter((l) => !l.startsWith('+')).length} +${newStart},${lines.filter((l) => !l.startsWith('-')).length} @@`,
    ...lines,
  ].join('\n');
}

describe('extractTouchedLines', () => {
  it('returns empty map for empty diff', () => {
    const result = extractTouchedLines('');
    assert.equal(result.size, 0);
  });

  it('tracks a single added line', () => {
    const diff = makeDiff('src/foo.ts', 1, 1, ['+const x = 1;']);
    const result = extractTouchedLines(diff);
    assert.ok(result.has('src/foo.ts'));
    assert.ok(result.get('src/foo.ts')!.has(1));
  });

  it('does not include removed lines', () => {
    const diff = makeDiff('src/foo.ts', 1, 1, ['-const x = 1;']);
    const result = extractTouchedLines(diff);
    assert.ok(result.has('src/foo.ts'));
    assert.equal(result.get('src/foo.ts')!.size, 0);
  });

  it('counts context lines in new-file numbering', () => {
    // hunk starting at new line 10, context then addition
    const diff = [
      'diff --git a/app.ts b/app.ts',
      '--- a/app.ts',
      '+++ b/app.ts',
      '@@ -10,3 +10,4 @@',
      ' const a = 1;',  // line 10 (context)
      ' const b = 2;',  // line 11 (context)
      '+const c = 3;',  // line 12 (added)
      ' const d = 4;',  // line 13 (context)
    ].join('\n');
    const result = extractTouchedLines(diff);
    assert.ok(result.get('app.ts')!.has(12), 'added line should be 12');
    assert.ok(!result.get('app.ts')!.has(10), 'context line 10 should not be marked touched');
    assert.ok(!result.get('app.ts')!.has(11), 'context line 11 should not be marked touched');
  });

  it('handles multiple files', () => {
    const diff = [
      'diff --git a/a.ts b/a.ts',
      '--- a/a.ts',
      '+++ b/a.ts',
      '@@ -1,1 +1,1 @@',
      '+line in a',
      'diff --git a/b.ts b/b.ts',
      '--- a/b.ts',
      '+++ b/b.ts',
      '@@ -5,1 +5,1 @@',
      '+line in b',
    ].join('\n');
    const result = extractTouchedLines(diff);
    assert.ok(result.get('a.ts')!.has(1));
    assert.ok(result.get('b.ts')!.has(5));
    assert.ok(!result.get('a.ts')!.has(5));
  });

  it('handles multiple hunks in the same file', () => {
    const diff = [
      'diff --git a/x.ts b/x.ts',
      '--- a/x.ts',
      '+++ b/x.ts',
      '@@ -1,1 +1,2 @@',
      '+first addition',
      ' context',
      '@@ -20,1 +21,2 @@',
      '+second addition',
      ' more context',
    ].join('\n');
    const result = extractTouchedLines(diff);
    const touched = result.get('x.ts')!;
    assert.ok(touched.has(1));
    assert.ok(touched.has(21));
    assert.ok(!touched.has(20));
  });

  it('ignores +++ file header lines', () => {
    const diff = [
      'diff --git a/foo.ts b/foo.ts',
      '--- a/foo.ts',
      '+++ b/foo.ts',
      '@@ -1,1 +1,1 @@',
      '+real addition',
    ].join('\n');
    const result = extractTouchedLines(diff);
    // The +++ line should NOT be counted as line 1
    const touched = result.get('foo.ts')!;
    assert.ok(touched.has(1), 'real addition at line 1 should be touched');
    assert.equal(touched.size, 1);
  });

  it('handles the PR #24 scenario: checkout@SHA replace on line 16', () => {
    // Simulates the actual diff where line 16 of guppy-scan.yml was changed
    const diff = [
      'diff --git a/.github/workflows/guppy-scan.yml b/.github/workflows/guppy-scan.yml',
      '--- a/.github/workflows/guppy-scan.yml',
      '+++ b/.github/workflows/guppy-scan.yml',
      '@@ -14,4 +14,4 @@',
      '     steps:',                                          // line 14 context
      '       - name: Checkout',                              // line 15 context
      '-        uses: actions/checkout@v4',                   // removed (old line 16)
      '+        uses: actions/checkout@abc1234',              // line 16 added
      '       - name: Run Guppy',                            // line 17 context
    ].join('\n');
    const result = extractTouchedLines(diff);
    const touched = result.get('.github/workflows/guppy-scan.yml')!;
    assert.ok(touched.has(16), 'line 16 should be touched after the checkout pin fix');
    assert.ok(!touched.has(14));
    assert.ok(!touched.has(15));
  });
});

describe('isStaleComment', () => {
  const touchedLines = new Map([
    ['.github/workflows/guppy-scan.yml', new Set([16, 21])],
  ]);

  it('returns true for a comment with line=null when original_line was touched', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: null, original_line: 16 };
    assert.equal(isStaleComment(comment, [], touchedLines), true);
  });

  it('returns true for a comment with line set when that line was touched', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: 21, original_line: 21 };
    assert.equal(isStaleComment(comment, [], touchedLines), true);
  });

  it('returns false when the line was not touched in the diff', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: 99, original_line: 99 };
    assert.equal(isStaleComment(comment, [], touchedLines), false);
  });

  it('returns false when an active finding still covers the same file+line', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: 21, original_line: 21 };
    const activeFindings = [{ file: '.github/workflows/guppy-scan.yml', line: 21 }];
    assert.equal(isStaleComment(comment, activeFindings, touchedLines), false);
  });

  it('returns false when both line and original_line are null', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: null, original_line: null };
    assert.equal(isStaleComment(comment, [], touchedLines), false);
  });

  it('returns false when the file was not in the diff at all', () => {
    const comment = { path: 'src/untouched.ts', line: 5, original_line: 5 };
    assert.equal(isStaleComment(comment, [], touchedLines), false);
  });

  it('uses line over original_line when both are set', () => {
    // line=21 is touched, original_line=99 is not — should resolve based on line
    const comment = { path: '.github/workflows/guppy-scan.yml', line: 21, original_line: 99 };
    assert.equal(isStaleComment(comment, [], touchedLines), true);
  });

  it('active finding on a different line does not block resolution', () => {
    const comment = { path: '.github/workflows/guppy-scan.yml', line: null, original_line: 16 };
    const activeFindings = [{ file: '.github/workflows/guppy-scan.yml', line: 21 }];
    assert.equal(isStaleComment(comment, activeFindings, touchedLines), true);
  });
});
