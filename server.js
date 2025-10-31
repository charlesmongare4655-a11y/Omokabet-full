// server.js
// Omokabet backend (Node.js + Express + PostgreSQL)
// Paste into server.js in your repo root.

const express = require('express');
const app = express();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Config - use environment variables on Render
const PORT = process.env.PORT || 4000;
const DATABASE_URL = process.env.DATABASE_URL || null;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || null; // optional admin bootstrap

if (!DATABASE_URL) {
  console.error('ERROR: set DATABASE_URL environment variable (Postgres connection string)');
  // do not exit so you can still run locally for quick tests, but DB ops will fail
}

// Postgres pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false // Render/Heroku style
});

app.use(express.json());

// Helper: run query
async function query(q, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(q, params);
    return res;
  } finally {
    client.release();
  }
}

// Initialize DB tables if not exists
async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
      balance NUMERIC DEFAULT 0,
      is_admin BOOLEAN DEFAULT false
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS matches (
      id SERIAL PRIMARY KEY,
      home TEXT NOT NULL,
      away TEXT NOT NULL,
      odds NUMERIC NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      match_id INTEGER REFERENCES matches(id),
      stake NUMERIC NOT NULL,
      status TEXT DEFAULT 'open',
      payout NUMERIC DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
      approved_by INTEGER REFERENCES users(id),
      approved_at TIMESTAMP WITH TIME ZONE
    );
  `);
}

// JWT middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing auth header' });
  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed auth header' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Admin middleware
async function adminMiddleware(req, res, next) {
  try {
    const { rows } = await query('SELECT is_admin FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0] || !rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

// Helpers
function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

// ROUTES

// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Register
app.post('/api/register', async (req, res) => {
  const { email, password, full_name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const isAdmin = ADMIN_EMAIL && ADMIN_EMAIL.toLowerCase() === email.toLowerCase();
    const q = await query(
      `INSERT INTO users (email, password_hash, full_name, is_admin) VALUES ($1,$2,$3,$4) RETURNING id,email,full_name,balance,is_admin`,
      [email, hash, full_name || null, isAdmin]
    );
    const user = q.rows[0];
    const token = createToken(user);
    res.json({ user, token });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  try {
    const { rows } = await query('SELECT id,email,password_hash,full_name,balance,is_admin FROM users WHERE email=$1', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    // strip password_hash
    delete user.password_hash;
    const token = createToken(user);
    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user profile (protected)
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await query('SELECT id,email,full_name,balance,is_admin FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create match (admin)
app.post('/api/matches', authMiddleware, adminMiddleware, async (req, res) => {
  const { home, away, odds } = req.body || {};
  if (!home || !away || !odds) return res.status(400).json({ error: 'Missing match data' });
  try {
    const { rows } = await query('INSERT INTO matches (home,away,odds) VALUES ($1,$2,$3) RETURNING *', [home, away, odds]);
    res.json({ match: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// List matches (public)
app.get('/api/matches', async (req, res) => {
  try {
    const { rows } = await query('SELECT id,home,away,odds,created_at FROM matches ORDER BY created_at DESC');
    res.json({ matches: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Request deposit (user creates a pending deposit request)
app.post('/api/deposits/request', authMiddleware, async (req, res) => {
  const { amount } = req.body || {};
  if (!amount || Number(amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
  try {
    const { rows } = await query('INSERT INTO deposits (user_id, amount, status) VALUES ($1,$2,$3) RETURNING id,amount,status', [req.user.id, amount, 'pending']);
    res.json({ deposit: rows[0], message: 'Deposit requested. Admin must approve (demo).' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Approve deposit (admin)
app.post('/api/deposits/approve', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Missing deposit id' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const depRes = await client.query('SELECT * FROM deposits WHERE id=$1 FOR UPDATE', [id]);
    if (!depRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Deposit not found' }); }
    const dep = depRes.rows[0];
    if (dep.status === 'approved') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Already approved' }); }
    // credit user balance
    const userRes = await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE', [dep.user_id]);
    const current = (userRes.rows[0] && userRes.rows[0].balance) ? Number(userRes.rows[0].balance) : 0;
    const newBal = current + Number(dep.amount);
    await client.query('UPDATE users SET balance=$1 WHERE id=$2', [newBal, dep.user_id]);
    await client.query('UPDATE deposits SET status=$1, approved_by=$2, approved_at=now() WHERE id=$3', ['approved', req.user.id, id]);
    await client.query('COMMIT');
    res.json({ success: true, newBalance: newBal });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Place bet (deducts wallet atomically and creates bet)
app.post('/api/bets/place', authMiddleware, async (req, res) => {
  const { match_id, stake } = req.body || {};
  if (!match_id || !stake || Number(stake) <= 0) return res.status(400).json({ error: 'Invalid bet data' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // lock user row
    const userRes = await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
    if (!userRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found' }); }
    const balance = Number(userRes.rows[0].balance || 0);
    if (balance < Number(stake)) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient balance' }); }

    // ensure match exists
    const matchRes = await client.query('SELECT * FROM matches WHERE id=$1', [match_id]);
    if (!matchRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Match not found' }); }

    // deduct balance and create bet
    const newBalance = balance - Number(stake);
    await client.query('UPDATE users SET balance=$1 WHERE id=$2', [newBalance, req.user.id]);
    const betRes = await client.query('INSERT INTO bets (user_id, match_id, stake, status) VALUES ($1,$2,$3,$4) RETURNING id', [req.user.id, match_id, stake, 'open']);

    await client.query('COMMIT');
    res.json({ success: true, betId: betRes.rows[0].id, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Payout bet (admin): supply betId and payout amount
app.post('/api/bets/payout', authMiddleware, adminMiddleware, async (req, res) => {
  const { betId, amount } = req.body || {};
  if (!betId || !amount) return res.status(400).json({ error: 'Missing params' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const betRes = await client.query('SELECT * FROM bets WHERE id=$1 FOR UPDATE', [betId]);
    if (!betRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Bet not found' }); }
    const bet = betRes.rows[0];
    if (bet.status === 'settled') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Already settled' }); }

    // credit winner
    const userRes = await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE', [bet.user_id]);
    const curBalance = Number(userRes.rows[0].balance || 0);
    const newBalance = curBalance + Number(amount);
    await client.query('UPDATE users SET balance=$1 WHERE id=$2', [newBalance, bet.user_id]);

    // update bet
    await client.query('UPDATE bets SET status=$1, payout=$2 WHERE id=$3', ['settled', amount, betId]);

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// List user's bets
app.get('/api/bets/my', authMiddleware, async (req, res) => {
  try {
    const { rows } = await query('SELECT b.id,b.match_id,b.stake,b.status,b.payout,b.created_at,m.home,m.away,m.odds FROM bets b LEFT JOIN matches m ON m.id=b.match_id WHERE b.user_id=$1 ORDER BY b.created_at DESC', [req.user.id]);
    res.json({ bets: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: list pending deposits
app.get('/api/admin/deposits', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await query('SELECT d.id,d.user_id,d.amount,d.status,d.created_at,u.email FROM deposits d LEFT JOIN users u ON u.id=d.user_id WHERE d.status=$1 ORDER BY d.created_at ASC', ['pending']);
    res.json({ deposits: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public: list top users (for admin view)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await query('SELECT id,email,full_name,balance,is_admin FROM users ORDER BY balance DESC LIMIT 100');
    res.json({ users: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Simple search or ping
app.get('/', (req, res) => res.send('Omokabet backend is running'));

// Start server after DB init
(async () => {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to initialize DB', err);
    process.exit(1);
  }
})();
