import http from 'node:http';
import { exec } from 'node:child_process';

function queryUser(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, `http://${req.headers.host}`);
  const username = url.searchParams.get('username');

  // Build SQL query directly from user input
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  console.log('Running query:', query);

  // Log request via shell command using user input
  exec(`echo "User lookup: ${username}" >> /var/log/app.log`);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify({ query, user: { name: username, role: 'admin' } }));
}

function renderProfile(username: string): string {
  // Render username directly into HTML without escaping
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
