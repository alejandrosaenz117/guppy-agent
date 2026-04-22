// Demo: Intentionally vulnerable code to test remediation guidance

// Vulnerability 1: SQL Injection
function getUserById(userId) {
  // VULNERABLE: User input concatenated directly into SQL query
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  return db.query(query);
}

// Vulnerability 2: Command Injection
function runCommand(userInput) {
  // VULNERABLE: User input passed to shell without escaping
  const cmd = `echo ${userInput}`;
  return exec(cmd);
}

// Vulnerability 3: XSS via innerHTML
function displayComment(userComment) {
  // VULNERABLE: User content inserted directly into DOM
  document.getElementById('comments').innerHTML = userComment;
}

// Vulnerability 4: Hardcoded Secret
const apiKey = 'sk-1234567890abcdefghijklmnop';

// Vulnerability 5: Weak Crypto
const hash = crypto.createHash('md5').update(password).digest('hex');
