// src/routes/apps.js — Developer portal: register & manage OAuth apps
const express = require('express');
const crypto = require('crypto');
const { pool } = require('../db');
const router = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// GET /apps — list my apps
router.get('/', requireAuth, async (req, res) => {
  const result = await pool.query(
    'SELECT id, name, description, client_id, redirect_uris, scopes, logo_url, website, created_at FROM oauth_apps WHERE owner_id = $1 ORDER BY created_at DESC',
    [req.session.userId]
  );
  res.json({ apps: result.rows });
});

// POST /apps — register a new OAuth app
router.post('/', requireAuth, async (req, res) => {
  const { name, description, redirect_uris, scopes, logo_url, website } = req.body;

  if (!name || !redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0)
    return res.status(400).json({ error: 'name and redirect_uris[] are required' });

  if (name.length > 64)
    return res.status(400).json({ error: 'App name too long (max 64 chars)' });

  // Validate redirect URIs
  for (const uri of redirect_uris) {
    try {
      const url = new URL(uri);
      if (!['http:', 'https:'].includes(url.protocol))
        return res.status(400).json({ error: `Invalid redirect_uri: ${uri}` });
    } catch {
      return res.status(400).json({ error: `Invalid redirect_uri: ${uri}` });
    }
  }

  const allowedScopes = ['profile', 'openid'];
  const requestedScopes = (scopes || ['profile']).filter(s => allowedScopes.includes(s));

  const client_id = 'sky_' + crypto.randomBytes(16).toString('hex');
  const client_secret = 'sks_' + crypto.randomBytes(32).toString('hex');

  try {
    const result = await pool.query(
      `INSERT INTO oauth_apps (owner_id, name, description, client_id, client_secret, redirect_uris, scopes, logo_url, website)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, name, client_id, client_secret, redirect_uris, scopes, created_at`,
      [req.session.userId, name, description || '', client_id, client_secret, redirect_uris, requestedScopes, logo_url || null, website || null]
    );
    res.status(201).json({ app: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /apps/:id — get app details (owner only)
router.get('/:id', requireAuth, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM oauth_apps WHERE id = $1 AND owner_id = $2',
    [req.params.id, req.session.userId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'App not found' });
  res.json({ app: result.rows[0] });
});

// PATCH /apps/:id — update app
router.patch('/:id', requireAuth, async (req, res) => {
  const { name, description, redirect_uris, logo_url, website } = req.body;
  try {
    const result = await pool.query(
      `UPDATE oauth_apps SET
        name = COALESCE($1, name),
        description = COALESCE($2, description),
        redirect_uris = COALESCE($3, redirect_uris),
        logo_url = COALESCE($4, logo_url),
        website = COALESCE($5, website)
       WHERE id = $6 AND owner_id = $7
       RETURNING id, name, description, client_id, redirect_uris, scopes, logo_url, website`,
      [name, description, redirect_uris, logo_url, website, req.params.id, req.session.userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'App not found' });
    res.json({ app: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /apps/:id/rotate-secret — regenerate client_secret
router.post('/:id/rotate-secret', requireAuth, async (req, res) => {
  const newSecret = 'sks_' + crypto.randomBytes(32).toString('hex');
  const result = await pool.query(
    'UPDATE oauth_apps SET client_secret = $1 WHERE id = $2 AND owner_id = $3 RETURNING client_secret',
    [newSecret, req.params.id, req.session.userId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'App not found' });
  res.json({ client_secret: result.rows[0].client_secret });
});

// DELETE /apps/:id
router.delete('/:id', requireAuth, async (req, res) => {
  const result = await pool.query(
    'DELETE FROM oauth_apps WHERE id = $1 AND owner_id = $2 RETURNING id',
    [req.params.id, req.session.userId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'App not found' });
  res.json({ ok: true });
});

// GET /apps/public/:client_id — public info about an app (for external sites building login buttons)
router.get('/public/:client_id', async (req, res) => {
  const result = await pool.query(
    'SELECT name, description, logo_url, website, scopes FROM oauth_apps WHERE client_id = $1',
    [req.params.client_id]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'App not found' });
  res.json({ app: result.rows[0] });
});

module.exports = router;
