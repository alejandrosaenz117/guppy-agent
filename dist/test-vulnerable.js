// Test file for validating Guppy MCP integration
import * as crypto from 'crypto';
// CWE-89: SQL Injection vulnerability
export function getUserData(id) {
    // SQL injection: user input directly in query
    const query = `SELECT * FROM users WHERE id = ${id}`;
    return query;
}
// CWE-95: Code Injection
export function executeUserCode(code) {
    // Direct eval of untrusted input
    return eval(code);
}
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
export function hashPassword(password) {
    // MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}
// Dead code - should be detected by chiasmus
function neverCalled() {
    console.log('This function is never invoked anywhere in the codebase');
}
// Another dead function
function alsoUnused(data) {
    return data;
}
//# sourceMappingURL=test-vulnerable.js.map