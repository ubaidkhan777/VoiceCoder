require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 4000;

//  MIDDLEWARE
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(__dirname));

//  POSTGRESQL CONNECTION POOL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log('✅  Connected to Supabase PostgreSQL'))
  .catch(err => console.error('❌  DB connection error:', err.message));

//  HELPERS
const JWT_SECRET     = process.env.JWT_SECRET || 'change_me_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function tokenExpiresAt() {
  const ms = 7 * 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ms);
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });

  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user  = payload;
    req.token = token;
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
}

//  ROUTES

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !name.trim())
    return res.status(400).json({ field: 'name', error: 'Name is required' });
  if (!email || !/\S+@\S+\.\S+/.test(email))
    return res.status(400).json({ field: 'email', error: 'Valid email is required' });
  if (!password || password.length < 6)
    return res.status(400).json({ field: 'password', error: 'Password must be at least 6 characters' });

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      'SELECT * FROM public.sp_create_user($1, $2, $3)',
      [name.trim(), email.toLowerCase().trim(), hash]
    );

    const row = result.rows[0];

    if (!row.success) {
      if (row.error_code === 'EMAIL_EXISTS')
        return res.status(409).json({ field: 'email', error: 'Email already in use' });
      return res.status(500).json({ error: 'Registration failed' });
    }

    const userId = row.user_id;
    const token  = signToken({ id: userId, name: name.trim(), email: email.toLowerCase().trim() });

    await pool.query(
      'SELECT public.sp_create_session($1, $2, $3, $4, $5)',
      [userId, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]
    );

    res.status(201).json({
      message: 'Account created',
      token,
      user: { id: userId, name: name.trim(), email: email.toLowerCase().trim() },
    });

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// POST /auth/signin
app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  try {
    const result = await pool.query(
      'SELECT * FROM public.sp_get_user_by_email($1)',
      [email.toLowerCase().trim()]
    );

    const user = result.rows[0];

    if (!user)
      return res.status(401).json({ field: 'email', error: 'No account found with this email' });

    if (!user.is_active)
      return res.status(403).json({ error: 'Account is disabled' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ field: 'password', error: 'Incorrect password' });

    await pool.query('SELECT public.sp_update_last_login($1)', [user.id]);

    const token = signToken({ id: user.id, name: user.name, email: user.email });

    await pool.query(
      'SELECT public.sp_create_session($1, $2, $3, $4, $5)',
      [user.id, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]
    );

    res.json({
      message: 'Signed in',
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: 'Server error during sign in' });
  }
});

// POST /auth/signout
app.post('/auth/signout', authMiddleware, async (req, res) => {
  try {
    await pool.query('SELECT public.sp_delete_session($1)', [req.token]);
    res.json({ message: 'Signed out' });
  } catch (err) {
    console.error('Signout error:', err);
    res.status(500).json({ error: 'Server error during sign out' });
  }
});

// GET /auth/me
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM public.sp_validate_session($1)',
      [req.token]
    );

    if (!result.rows.length)
      return res.status(401).json({ error: 'Session expired' });

    const { id, name, email } = result.rows[0];
    res.json({ user: { id, name, email } });

  } catch (err) {
    console.error('/auth/me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date() }));

// COMPILE PROXY — avoids CORS issues from the browser

// Paiza.io proxy
app.post('/compile/paiza', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code provided' });
  try {
    const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
    const cr = await fetch(
      'https://api.paiza.io/runners/create?source_code=' + encodeURIComponent(code) + '&language=cpp&api_key=guest',
      { method: 'POST' }
    );
    if (!cr.ok) return res.json({ success: false, error: 'Paiza create failed: ' + cr.status });
    const { id } = await cr.json();
    await new Promise(r => setTimeout(r, 3000));
    const gr = await fetch('https://api.paiza.io/runners/get_details?id=' + id + '&api_key=guest');
    if (!gr.ok) return res.json({ success: false, error: 'Paiza details failed: ' + gr.status });
    const d = await gr.json();
    if (d.build_result === 'failure')
      return res.json({ success: false, error: d.build_stderr || 'Build failed' });
    return res.json({ success: true, output: d.stdout || '(no output)' });
  } catch (err) {
    console.error('Paiza proxy error:', err);
    res.json({ success: false, error: err.message });
  }
});

// JDoodle proxy
app.post('/compile/jdoodle', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code provided' });
  const clientId     = process.env.JDOODLE_CLIENT_ID;
  const clientSecret = process.env.JDOODLE_CLIENT_SECRET;
  if (!clientId || !clientSecret)
    return res.json({ success: false, error: 'JDoodle credentials not configured on server' });
  try {
    const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
    const r = await fetch('https://api.jdoodle.com/v1/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId, clientSecret, script: code, language: 'cpp17', versionIndex: '0' })
    });
    if (!r.ok) return res.json({ success: false, error: 'JDoodle HTTP ' + r.status });
    const d = await r.json();
    if (d.error) return res.json({ success: false, error: d.error });
    if (d.output?.toLowerCase().includes('error:'))
      return res.json({ success: false, error: d.output });
    return res.json({ success: true, output: d.output || '' });
  } catch (err) {
    console.error('JDoodle proxy error:', err);
    res.json({ success: false, error: err.message });
  }
});

//  START SERVER
app.listen(PORT, () => {
  console.log(`🚀  VoiceCoder server running on http://localhost:${PORT}`);
  console.log(`🌐  Open: http://localhost:${PORT}/voicecoder_ai_sql.html`);
});
