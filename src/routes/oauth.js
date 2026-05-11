// src/routes/oauth.js  — The actual OAuth2 provider logic
const express = require('express');
const crypto = require('crypto');
const { pool } = require('../db');
const router = express.Router();

const SCOPES_AVAILABLE = {
  profile: 'Access your username and display name',
  email_placeholder: 'Reserved (no email system)',
  openid: 'Confirm your Skybound identity',
};

function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

// ─── GET /oauth/authorize ────────────────────────────────────────────────────
// The page external sites redirect users to for "Login with Skybound"
router.get('/authorize', async (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  // Validate required params
  if (!client_id || !redirect_uri || response_type !== 'code')
    return res.status(400).send('Invalid authorization request');

  try {
    // Look up the registered app
    const appResult = await pool.query(
      'SELECT * FROM oauth_apps WHERE client_id = $1', [client_id]
    );
    const app = appResult.rows[0];
    if (!app) return res.status(400).send('Unknown client_id');

    // Validate redirect_uri
    if (!app.redirect_uris.includes(redirect_uri))
      return res.status(400).send('redirect_uri not registered for this app');

    const requestedScopes = (scope || 'profile').split(' ').filter(s => SCOPES_AVAILABLE[s]);
    if (requestedScopes.length === 0) requestedScopes.push('profile');

    // If user is already logged in, show the consent screen directly
    // If not, redirect to login page with the oauth params preserved
    const isLoggedIn = !!req.session.userId;

    // Store oauth params in session for after login
    req.session.oauthRequest = { client_id, redirect_uri, response_type, scope: requestedScopes.join(' '), state, code_challenge, code_challenge_method };

    if (!isLoggedIn) {
      // Redirect to login UI with a flag
      return res.redirect('/login?next=oauth');
    }

    // Show consent page
    const userResult = await pool.query('SELECT id, username, display_name FROM users WHERE id = $1', [req.session.userId]);
    const user = userResult.rows[0];

    // Check if already authorized this app with same/superset scopes
    const existingAuth = await pool.query(
      'SELECT scopes FROM user_authorizations WHERE user_id = $1 AND app_id = $2',
      [user.id, app.id]
    );

    const alreadyAuthorized = existingAuth.rows[0] &&
      requestedScopes.every(s => existingAuth.rows[0].scopes.includes(s));

    if (alreadyAuthorized) {
      // Auto-approve, skip consent
      return issueCode(res, user.id, app, redirect_uri, requestedScopes, state, code_challenge, code_challenge_method);
    }

    // Render consent page
    const scopeDescriptions = requestedScopes.map(s => ({ key: s, desc: SCOPES_AVAILABLE[s] || s }));
    res.send(renderConsentPage(user, app, scopeDescriptions, req.query));

  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// ─── POST /oauth/authorize ───────────────────────────────────────────────────
// User clicked Allow/Deny on the consent screen
router.post('/authorize', async (req, res) => {
  if (!req.session.userId) return res.status(401).send('Not authenticated');
  const { client_id, redirect_uri, scope, state, allow, code_challenge, code_challenge_method } = req.body;

  if (allow !== 'true') {
    // User denied — redirect with error
    const url = new URL(redirect_uri);
    url.searchParams.set('error', 'access_denied');
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
  }

  try {
    const appResult = await pool.query('SELECT * FROM oauth_apps WHERE client_id = $1', [client_id]);
    const app = appResult.rows[0];
    if (!app || !app.redirect_uris.includes(redirect_uri))
      return res.status(400).send('Invalid request');

    const scopes = (scope || 'profile').split(' ');

    // Save authorization
    await pool.query(
      `INSERT INTO user_authorizations (user_id, app_id, scopes)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, app_id) DO UPDATE SET scopes = $3, granted_at = NOW()`,
      [req.session.userId, app.id, scopes]
    );

    return issueCode(res, req.session.userId, app, redirect_uri, scopes, state, code_challenge, code_challenge_method);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

async function issueCode(res, userId, app, redirectUri, scopes, state, codeChallenge, codeChallengeMethod) {
  const code = generateToken(24);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  await pool.query(
    `INSERT INTO auth_codes (code, user_id, app_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [code, userId, app.id, scopes, redirectUri, codeChallenge || null, codeChallengeMethod || null, expiresAt]
  );

  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(url.toString());
}

// ─── POST /oauth/token ───────────────────────────────────────────────────────
// Exchange auth code for access_token + refresh_token (or refresh for new tokens)
router.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token, code_verifier } = req.body;

  // Support Basic auth header too
  let appClientId = client_id;
  let appClientSecret = client_secret;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString();
    [appClientId, appClientSecret] = decoded.split(':');
  }

  try {
    if (grant_type === 'authorization_code') {
      // Validate app credentials
      const appResult = await pool.query(
        'SELECT * FROM oauth_apps WHERE client_id = $1 AND client_secret = $2',
        [appClientId, appClientSecret]
      );
      const app = appResult.rows[0];
      if (!app) return res.status(401).json({ error: 'invalid_client' });

      // Validate code
      const codeResult = await pool.query(
        `SELECT * FROM auth_codes WHERE code = $1 AND used = FALSE AND expires_at > NOW()`,
        [code]
      );
      const authCode = codeResult.rows[0];
      if (!authCode || authCode.app_id !== app.id || authCode.redirect_uri !== redirect_uri)
        return res.status(400).json({ error: 'invalid_grant' });

      // PKCE verification
      if (authCode.code_challenge) {
        if (!code_verifier) return res.status(400).json({ error: 'invalid_grant', detail: 'code_verifier required' });
        if (authCode.code_challenge_method === 'S256') {
          const expected = crypto.createHash('sha256').update(code_verifier).digest('base64url');
          if (expected !== authCode.code_challenge)
            return res.status(400).json({ error: 'invalid_grant', detail: 'PKCE mismatch' });
        }
      }

      // Mark code used
      await pool.query('UPDATE auth_codes SET used = TRUE WHERE code = $1', [code]);

      // Issue tokens
      return issueTokens(res, authCode.user_id, app.id, authCode.scopes);

    } else if (grant_type === 'refresh_token') {
      const rt = await pool.query(
        'SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()',
        [refresh_token]
      );
      if (!rt.rows[0]) return res.status(400).json({ error: 'invalid_grant' });

      const appResult = await pool.query('SELECT * FROM oauth_apps WHERE client_id = $1 AND client_secret = $2', [appClientId, appClientSecret]);
      if (!appResult.rows[0] || appResult.rows[0].id !== rt.rows[0].app_id)
        return res.status(401).json({ error: 'invalid_client' });

      // Delete old refresh token
      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refresh_token]);
      return issueTokens(res, rt.rows[0].user_id, rt.rows[0].app_id, rt.rows[0].scopes);

    } else {
      res.status(400).json({ error: 'unsupported_grant_type' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

async function issueTokens(res, userId, appId, scopes) {
  const accessToken = generateToken(32);
  const refreshToken = generateToken(40);
  const accessExpires = new Date(Date.now() + 60 * 60 * 1000);      // 1 hour
  const refreshExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

  await pool.query(
    'INSERT INTO access_tokens (token, user_id, app_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5)',
    [accessToken, userId, appId, scopes, accessExpires]
  );
  await pool.query(
    'INSERT INTO refresh_tokens (token, user_id, app_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5)',
    [refreshToken, userId, appId, scopes, refreshExpires]
  );

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: scopes.join(' '),
  });
}

// ─── GET /oauth/userinfo ─────────────────────────────────────────────────────
// External apps call this with access_token to get user data
router.get('/userinfo', async (req, res) => {
  const bearer = req.headers.authorization?.replace('Bearer ', '');
  if (!bearer) return res.status(401).json({ error: 'unauthorized' });

  try {
    const tokenResult = await pool.query(
      'SELECT * FROM access_tokens WHERE token = $1 AND expires_at > NOW()', [bearer]
    );
    const token = tokenResult.rows[0];
    if (!token) return res.status(401).json({ error: 'invalid_token' });

    const userResult = await pool.query(
      'SELECT id, username, display_name, avatar_url, bio, created_at FROM users WHERE id = $1',
      [token.user_id]
    );
    const user = userResult.rows[0];
    if (!user) return res.status(401).json({ error: 'user_not_found' });

    // Return based on granted scopes
    const response = { sub: user.id };
    if (token.scopes.includes('profile') || token.scopes.includes('openid')) {
      response.username = user.username;
      response.display_name = user.display_name;
      response.avatar_url = user.avatar_url;
      response.bio = user.bio;
      response.created_at = user.created_at;
    }

    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ─── POST /oauth/revoke ──────────────────────────────────────────────────────
router.post('/revoke', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });
  await pool.query('DELETE FROM access_tokens WHERE token = $1', [token]);
  await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
  res.json({ ok: true });
});

// ─── GET /oauth/.well-known/openid-configuration ─────────────────────────────
router.get('/.well-known/openid-configuration', (req, res) => {
  const base = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    revocation_endpoint: `${base}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: Object.keys(SCOPES_AVAILABLE),
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    code_challenge_methods_supported: ['S256', 'plain'],
  });
});

// ─── Consent Page HTML ───────────────────────────────────────────────────────
function renderConsentPage(user, app, scopeDescriptions, query) {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = query;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorize – Skybound</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --sky: #0EA5E9;
    --sky-dark: #0284C7;
    --ink: #0F172A;
    --mist: #F0F9FF;
    --cloud: #E0F2FE;
    --slate: #64748B;
    --danger: #EF4444;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'DM Sans', sans-serif;
    background: linear-gradient(135deg, #0F172A 0%, #0C4A6E 50%, #0F172A 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
  }
  .card {
    background: white;
    border-radius: 20px;
    width: 100%;
    max-width: 440px;
    overflow: hidden;
    box-shadow: 0 32px 80px rgba(0,0,0,0.4);
  }
  .card-header {
    background: linear-gradient(135deg, var(--ink), #0C4A6E);
    padding: 2rem;
    text-align: center;
  }
  .logo {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.5rem;
    color: var(--sky);
    letter-spacing: -0.5px;
  }
  .logo span { color: white; }
  .arrow {
    color: rgba(255,255,255,0.3);
    font-size: 1.5rem;
    margin: 0.75rem 0;
  }
  .app-name {
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 1.2rem;
    color: white;
  }
  .app-meta { color: rgba(255,255,255,0.5); font-size: 0.8rem; margin-top: 0.25rem; }
  .card-body { padding: 2rem; }
  .greeting {
    font-size: 0.9rem;
    color: var(--slate);
    margin-bottom: 1.5rem;
  }
  .greeting strong { color: var(--ink); }
  .scopes-title {
    font-family: 'Syne', sans-serif;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--slate);
    margin-bottom: 0.75rem;
  }
  .scope-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem;
    background: var(--mist);
    border-radius: 10px;
    margin-bottom: 0.5rem;
  }
  .scope-icon { font-size: 1.1rem; }
  .scope-text { font-size: 0.85rem; color: var(--ink); }
  .actions {
    display: flex;
    gap: 0.75rem;
    margin-top: 1.75rem;
  }
  .btn {
    flex: 1;
    padding: 0.85rem;
    border-radius: 12px;
    border: none;
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-deny { background: #F1F5F9; color: var(--slate); }
  .btn-deny:hover { background: #E2E8F0; }
  .btn-allow { background: var(--sky); color: white; }
  .btn-allow:hover { background: var(--sky-dark); transform: translateY(-1px); }
  .footer-note {
    text-align: center;
    font-size: 0.75rem;
    color: var(--slate);
    margin-top: 1.25rem;
  }
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="logo">Sky<span>bound</span></div>
    <div class="arrow">↕</div>
    <div class="app-name">${escHtml(app.name)}</div>
    ${app.website ? `<div class="app-meta">${escHtml(app.website)}</div>` : ''}
  </div>
  <div class="card-body">
    <p class="greeting">Hi, <strong>@${escHtml(user.username)}</strong> — <strong>${escHtml(app.name)}</strong> is requesting access to your Skybound account.</p>
    <div class="scopes-title">This app will be able to:</div>
    ${scopeDescriptions.map(s => `
    <div class="scope-item">
      <span class="scope-icon">✦</span>
      <span class="scope-text">${escHtml(s.desc)}</span>
    </div>`).join('')}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escHtml(client_id)}">
      <input type="hidden" name="redirect_uri" value="${escHtml(redirect_uri)}">
      <input type="hidden" name="scope" value="${escHtml(scope)}">
      <input type="hidden" name="state" value="${escHtml(state || '')}">
      <input type="hidden" name="code_challenge" value="${escHtml(code_challenge || '')}">
      <input type="hidden" name="code_challenge_method" value="${escHtml(code_challenge_method || '')}">
      <div class="actions">
        <button class="btn btn-deny" type="submit" name="allow" value="false">Deny</button>
        <button class="btn btn-allow" type="submit" name="allow" value="true">Allow Access</button>
      </div>
    </form>
    <p class="footer-note">You can revoke this access anytime from your Skybound account settings.</p>
  </div>
</div>
</body>
</html>`;
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

module.exports = router;
