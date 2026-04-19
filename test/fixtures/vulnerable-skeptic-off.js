// Validation fixture: skeptic_pass=false (single-pass mode)
const { exec } = require('child_process');

function runReport(filename) {
  // Command injection — filename passed directly to shell
  exec('cat reports/' + filename, (err, stdout) => {
    console.log(stdout);
  });
}

module.exports = { runReport };
