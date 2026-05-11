// src/routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../db');
const router = express.Router();

// POST /auth/register
router.post('/register', async (req, res) => {
  const { username, password, display_name } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });

  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3-32 chars, letters/numbers/underscores only' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, display_name, created_at`,
      [username.toLowerCase(), display_name || username, hash]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    res.status(201).json({ user: { id: user.id, username: user.username, display_name: user.display_name } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already taken' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username.toLowerCase()]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.userId = user.id;
    res.json({ user: { id: user.id, username: user.username, display_name: user.display_name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// GET /auth/me — check current session
router.get('/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  try {
    const result = await pool.query(
      'SELECT id, username, display_name, avatar_url, bio, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );
    if (!result.rows[0]) return res.status(401).json({ error: 'Not logged in' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /auth/profile — update own profile
router.patch('/profile', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { display_name, bio, avatar_url } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET display_name = COALESCE($1, display_name),
       bio = COALESCE($2, bio), avatar_url = COALESCE($3, avatar_url),
       updated_at = NOW()
       WHERE id = $4 RETURNING id, username, display_name, bio, avatar_url`,
      [display_name, bio, avatar_url, req.session.userId]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /auth/authorizations — list apps the user has authorized
router.get('/authorizations', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  try {
    const result = await pool.query(
      `SELECT ua.app_id, ua.scopes, ua.granted_at, a.name, a.website, a.logo_url
       FROM user_authorizations ua
       JOIN oauth_apps a ON a.id = ua.app_id
       WHERE ua.user_id = $1
       ORDER BY ua.granted_at DESC`,
      [req.session.userId]
    );
    res.json({ authorizations: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /auth/authorizations/:appId — revoke app access + tokens
router.delete('/authorizations/:appId', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  try {
    await pool.query('DELETE FROM user_authorizations WHERE user_id = $1 AND app_id = $2', [req.session.userId, req.params.appId]);
    await pool.query('DELETE FROM access_tokens WHERE user_id = $1 AND app_id = $2', [req.session.userId, req.params.appId]);
    await pool.query('DELETE FROM refresh_tokens WHERE user_id = $1 AND app_id = $2', [req.session.userId, req.params.appId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
