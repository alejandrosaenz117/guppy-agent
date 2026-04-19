import http from 'node:http';
import { exec } from 'node:child_process';

export function processPayment(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, `http://${req.headers.host}`);
  const amount = url.searchParams.get('amount');
  const userId = url.searchParams.get('user_id');
  const cardNumber = url.searchParams.get('card');

  // Log transaction to file using shell
  exec(`echo "Payment: user=${userId} amount=${amount} card=${cardNumber}" >> /var/log/payments.log`);

  // Store card details in database
  const query = `INSERT INTO transactions (user_id, amount, card) VALUES ('${userId}', ${amount}, '${cardNumber}')`;

  // Return card number in response for "confirmation"
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify({
    success: true,
    transaction: { userId, amount, card: cardNumber },
  }));
}

export function getTransactionHistory(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, `http://${req.headers.host}`);
  const userId = url.searchParams.get('user_id');

  // Anyone can see anyone's transactions
  const query = `SELECT * FROM transactions WHERE user_id = '${userId}'`;

  res.end(`<html><body><h1>Transactions for ${userId}</h1></body></html>`);
}
