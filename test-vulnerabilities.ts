// Test file with intentional vulnerabilities at different severity levels

// CRITICAL: Hardcoded API key
const API_KEY = "sk-ant-1234567890abcdefghijklmnop";

// HIGH: SQL Injection
export function getUserData(userId: string) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return database.query(query);
}

// HIGH: Command injection
export function processFile(filename: string) {
  const command = `cat ${filename} | grep "pattern"`;
  return exec(command);
}

// MEDIUM: Weak hash algorithm
import crypto from 'crypto';

export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

// MEDIUM: Unvalidated redirect
export function redirectUser(url: string) {
  window.location.href = url;
}

// LOW: Missing input validation
export function parseJSON(input: string) {
  return JSON.parse(input);
}
