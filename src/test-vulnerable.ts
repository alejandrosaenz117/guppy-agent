// Test file for validating Guppy MCP integration
import * as crypto from 'crypto';
import * as mysql from 'mysql';

// CWE-89: SQL Injection vulnerability
export function getUserData(id: string) {
  const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'users',
  });

  // SQL injection: user input directly in query
  const query = `SELECT * FROM users WHERE id = ${id}`;
  return db.query(query);
}

// CWE-95: Code Injection
export function executeUserCode(code: string) {
  // Direct eval of untrusted input
  return eval(code);
}

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
export function hashPassword(password: string): string {
  // MD5 is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// Dead code - should be detected by chiasmus
function neverCalled() {
  console.log('This function is never invoked anywhere in the codebase');
}

// Another dead function
function alsoUnused(data: unknown) {
  return data;
}
