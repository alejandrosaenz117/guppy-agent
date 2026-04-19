import http from 'node:http';
import { exec } from 'node:child_process';

const DB_PASSWORD = 'supersecret123';
const ADMIN_TOKEN = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAAA';

function queryUser(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, `http://${req.headers.host}`);
  const username = url.searchParams.get('username');

  // Fetch user from database
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  console.log('Running query:', query);

  // Run system command to log request
  exec(`echo "User lookup: ${username}" >> /var/log/app.log`);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify({ query, user: { name: username, role: 'admin' } }));
}

function renderProfile(username: string): string {
  return `<div class="profile"><h1>Welcome, ${username}!</h1></div>`;
}

const server = http.createServer((req, res) => {
  if (req.url?.startsWith('/user')) {
    queryUser(req, res);
  } else {
    res.end(renderProfile(req.headers['x-username'] as string));
  }
});

server.listen(3000);
