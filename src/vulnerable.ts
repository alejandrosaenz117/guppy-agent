import http from 'node:http';
import { exec } from 'node:child_process';
import { createHash } from 'node:crypto';

export function login(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, `http://${req.headers.host}`);
  const username = url.searchParams.get('username');
  const password = url.searchParams.get('password');

  // Hash password with MD5
  const hash = createHash('md5').update(password!).digest('hex');

  // Query database directly from user input
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hash}'`;

  // Log login attempt using shell with unsanitized input
  exec(`echo "${username} attempted login" >> /var/log/auth.log`);

  res.setHeader('Set-Cookie', `session=${username}; HttpOnly=false; SameSite=None`);
  res.end(JSON.stringify({ success: true, user: username }));
}

export function resetPassword(req: http.IncomingMessage, res: http.ServerResponse) {
  const body: any = req.headers['x-request-body'];
  const newPassword = body.password;

  exec(`echo ${newPassword} | passwd`);

  res.end('Password reset');
}
