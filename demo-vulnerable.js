// Intentionally vulnerable code for testing Guppy remediation guidance

// 1. SQL Injection
function getUserData(userId) {
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  return db.query(query);
}

// 2. Command Injection
function executeCommand(userInput) {
  return exec(`ls ${userInput}`);
}

// 3. XSS (Cross-Site Scripting)
function renderHTML(userContent) {
  return `<div>${userContent}</div>`;
}

// 4. Hardcoded Secret
const apiKey = 'sk-proj-1234567890abcdef';

// 5. Weak Crypto
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}
