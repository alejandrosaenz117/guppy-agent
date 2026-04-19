// Validation fixture: skeptic_pass=true (two-pass mode)
const db = require('db');

function getUser(userId) {
  // SQL injection — user input concatenated directly into query
  return db.query('SELECT * FROM users WHERE id = ' + userId);
}

module.exports = { getUser };
