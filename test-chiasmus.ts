import * as mysql from 'mysql';

// Test case 1: SQL injection vulnerability
function getUserData(userId: string) {
  const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'password' });
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(query);
}

// Test case 2: Command injection vulnerability
function processFile(filename: string) {
  const exec = require('child_process').exec;
  const cmd = `cat ${filename}`;
  return exec(cmd);
}

// Test case 3: Hardcoded secret
const apiKey = 'sk-proj-abcd1234efgh5678ijkl9012mnop3456';

// Test case 4: Unsafe deserialization
function parseUserInput(data: string) {
  return eval(`(${data})`);
}

// Test case 5: XSS vulnerability in React
function renderUserComment(comment: string) {
  return `<div>${comment}</div>`;
}

export { getUserData, processFile, parseUserInput, renderUserComment };
