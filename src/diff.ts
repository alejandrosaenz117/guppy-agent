export function extractTouchedLines(diff: string): Map<string, Set<number>> {
  const result = new Map<string, Set<number>>();
  let currentFile = '';
  let newLineNum = 0;

  for (const line of diff.split('\n')) {
    const fileMatch = line.match(/^diff --git a\/.+ b\/(.+)$/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      if (!result.has(currentFile)) result.set(currentFile, new Set());
      continue;
    }
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLineNum = parseInt(hunkMatch[1], 10);
      continue;
    }
    if (!currentFile) continue;
    if (line.startsWith('+') && !line.startsWith('+++')) {
      result.get(currentFile)!.add(newLineNum);
      newLineNum++;
    } else if (!line.startsWith('-')) {
      newLineNum++;
    }
  }

  return result;
}

// Determines whether a PR review comment should be resolved as stale.
// A comment is stale when:
//   1. No active finding targets the same file+line, AND
//   2. The specific line was actually touched in this diff
//      (so we don't resolve comments on untouched lines where the issue may still exist).
//
// GitHub sets comment.line = null for comments on outdated diff positions; use original_line
// as the fallback so outdated comments are still evaluated correctly.
export function isStaleComment(
  comment: { path: string; line: number | null; original_line: number | null },
  activeFindings: Array<{ file: string; line: number }>,
  touchedLines: Map<string, Set<number>>
): boolean {
  const commentLine = comment.line ?? comment.original_line;
  if (commentLine === null) return false;
  if (activeFindings.some((f) => f.file === comment.path && f.line === commentLine)) return false;
  return touchedLines.get(comment.path)?.has(commentLine) ?? false;
}
