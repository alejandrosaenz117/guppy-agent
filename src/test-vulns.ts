// Test vulnerabilities for e2e scanning

export function vulnerableSqlQuery(userId: string) {
  const query = `SELECT * FROM users WHERE id = '${userId}'`; // SQL injection
  return query;
}

export function vulnerableXss(userInput: string) {
  document.body.innerHTML = userInput; // XSS vulnerability
}
