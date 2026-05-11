// src/index.js — Skybound Auth Server
'use strict';

// Load .env only in local dev — Render injects vars directly
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (_) {}
}

const express      = require('express');
const session      = require('express-session');
const pgSession    = require('connect-pg-simple')(session);
const cors         = require('cors');
const path         = require('path');
const rateLimit    = require('express-rate-limit');
const { pool }     = require('./db');

const app      = express();
const PORT     = parseInt(process.env.PORT || '3000', 10);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const IS_PROD  = process.env.NODE_ENV === 'production';

// ─── Trust Render's proxy ────────────────────────────────────────────────────
app.set('trust proxy', 1);

// ─── CORS ────────────────────────────────────────────────────────────────────
// Token + userinfo endpoints must accept cross-origin requests from any site
app.use('/oauth/token',              cors({ origin: '*' }));
app.use('/oauth/userinfo',           cors({ origin: '*' }));
app.use('/oauth/.well-known',        cors({ origin: '*' }));

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
  : [BASE_URL, 'http://localhost:3000'];

app.use(cors({ origin: allowedOrigins, credentials: true }));

// ─── Body parsers ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Sessions — stored in Postgres so they survive Render restarts ───────────
app.use(session({
  store: new pgSession({
    pool,
    tableName: 'sessions',
    createTableIfMissing: true,   // auto-creates the sessions table
  }),
  secret:            process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  rolling:           true,
  cookie: {
    secure:   IS_PROD,   // HTTPS-only on Render
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
  },
}));

// ─── Rate limiting ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
});
app.use('/auth/login',    authLimiter);
app.use('/auth/register', authLimiter);
app.use('/oauth/token',   authLimiter);

// ─── Static UI ───────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));

// ─── API routes ───────────────────────────────────────────────────────────────
app.use('/auth',  require('./routes/auth'));
app.use('/oauth', require('./routes/oauth'));
app.use('/apps',  require('./routes/apps'));

// ─── Health check (also verifies DB) ─────────────────────────────────────────
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', ts: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'error', db: err.message });
  }
});

// ─── SPA fallback — serve index.html for all unmatched routes ────────────────
app.use((_req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Skybound Auth  →  ${BASE_URL}  (port ${PORT})`);
  console.log(`   Discovery: ${BASE_URL}/oauth/.well-known/openid-configuration`);
});

module.exports = app;
