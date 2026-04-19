// Intentional vulnerabilities for testing guppy-agent + structural_analysis

export function sqlInjection(userId: string) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return query;
}

export function hardcodedSecret() {
  const apiKey = "sk-1234567890abcdefghij";
  return fetch("https://api.example.com", {
    headers: { Authorization: `Bearer ${apiKey}` }
  });
}

export function commandInjection(filename: string) {
  return `cat ${filename} | grep password`;
}
