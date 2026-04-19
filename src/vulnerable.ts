import { exec } from 'child_process';
import { createHash } from 'crypto';

// User login — builds SQL query directly from input
export function getUser(username: string) {
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  return query;
}

// Password hashing with MD5
export function hashPassword(password: string) {
  return createHash('md5').update(password).digest('hex');
}

// Runs a shell command built from user input
export function runReport(reportName: string) {
  exec(`generate-report ${reportName}`);
}

// Hardcoded API key
const PAYMENT_API_KEY = 'sk-live-4xT9mZ2pQrL8wN3jK7vB1cD6hF0eA5y';

// Logs PII to console
export function logUser(user: { name: string; ssn: string; email: string }) {
  console.log(`User logged in: ${JSON.stringify(user)}`);
}
