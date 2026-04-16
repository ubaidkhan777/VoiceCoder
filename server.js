require('dotenv').config();
const express   = require('express');
const mssql     = require('mssql');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');

const app  = express();
const PORT = process.env.PORT || 4000;

//  MIDDLEWARE
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(__dirname));

//  SQL SERVER CONNECTION POOL
const sqlConfig = {
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME || 'VoiceCoderDB',
  options: {
    encrypt:                process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: process.env.DB_TRUST_CERT === 'true',
  },
  port: 1433,
};

let pool;
async function getPool() {
  if (!pool) {
    pool = await mssql.connect(sqlConfig);
    console.log('✅  Connected to SQL Server:', sqlConfig.server, '/', sqlConfig.database);
  }
  return pool;
}

//  HELPERS
const JWT_SECRET      = process.env.JWT_SECRET || 'change_me_in_production';
const JWT_EXPIRES_IN  = process.env.JWT_EXPIRES_IN || '7d';

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
    const db   = await getPool();
    const hash = await bcrypt.hash(password, 12);

    const result = await db.request()
      .input('name',     mssql.NVarChar(100), name.trim())
      .input('email',    mssql.NVarChar(255), email.toLowerCase().trim())
      .input('password', mssql.NVarChar(255), hash)
      .execute('sp_CreateUser');

    const row = result.recordset[0];

    if (!row.success) {
      if (row.error_code === 'EMAIL_EXISTS')
        return res.status(409).json({ field: 'email', error: 'Email already in use' });
      return res.status(500).json({ error: 'Registration failed' });
    }

    const userId = row.user_id;
    const token  = signToken({ id: userId, name: name.trim(), email: email.toLowerCase().trim() });

    await db.request()
      .input('user_id',    mssql.Int,          userId)
      .input('token',      mssql.NVarChar(512), token)
      .input('expires_at', mssql.DateTime2,     tokenExpiresAt())
      .input('ip_address', mssql.NVarChar(45),  req.ip || null)
      .input('user_agent', mssql.NVarChar(500), req.headers['user-agent'] || null)
      .execute('sp_CreateSession');

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
    const db = await getPool();

    const result = await db.request()
      .input('email', mssql.NVarChar(255), email.toLowerCase().trim())
      .execute('sp_GetUserByEmail');

    const user = result.recordset[0];

    if (!user)
      return res.status(401).json({ field: 'email', error: 'No account found with this email' });

    if (!user.is_active)
      return res.status(403).json({ error: 'Account is disabled' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ field: 'password', error: 'Incorrect password' });

    await db.request()
      .input('user_id', mssql.Int, user.id)
      .execute('sp_UpdateLastLogin');

    const token = signToken({ id: user.id, name: user.name, email: user.email });

    await db.request()
      .input('user_id',    mssql.Int,          user.id)
      .input('token',      mssql.NVarChar(512), token)
      .input('expires_at', mssql.DateTime2,     tokenExpiresAt())
      .input('ip_address', mssql.NVarChar(45),  req.ip || null)
      .input('user_agent', mssql.NVarChar(500), req.headers['user-agent'] || null)
      .execute('sp_CreateSession');

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
    const db = await getPool();
    await db.request()
      .input('token', mssql.NVarChar(512), req.token)
      .execute('sp_DeleteSession');

    res.json({ message: 'Signed out' });
  } catch (err) {
    console.error('Signout error:', err);
    res.status(500).json({ error: 'Server error during sign out' });
  }
});

// GET /auth/me
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const db = await getPool();
    const result = await db.request()
      .input('token', mssql.NVarChar(512), req.token)
      .execute('sp_ValidateSession');

    if (!result.recordset.length)
      return res.status(401).json({ error: 'Session expired' });

    const { id, name, email } = result.recordset[0];
    res.json({ user: { id, name, email } });

  } catch (err) {
    console.error('/auth/me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date() }));

//  START SERVER
app.listen(PORT, () => {
  console.log(`🚀  VoiceCoder auth server running on http://localhost:${PORT}`);
  console.log(`🌐  Open the app at: http://localhost:${PORT}/voicecoder_ai_sql.html`);
});
