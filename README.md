# Skybound Auth 🌤️

A **self-hosted OAuth2 + OpenID Connect provider** — so other websites can add "**Login with Skybound**" buttons to their apps.

---

## What this does

- Users create Skybound accounts (username + password, no email needed)
- Developers register OAuth2 apps in the dashboard
- External sites redirect users to Skybound to authorize
- Skybound issues access tokens; apps call `/oauth/userinfo` to get user data
- Full PKCE support, refresh tokens, token revocation

---

## Deploy to Render (free tier)

### Option A — One-click with render.yaml

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect your repo — Render reads `render.yaml` and creates:
   - A **web service** (Node.js)
   - A **PostgreSQL database** (free tier)
4. Set `BASE_URL` env var to your actual Render URL (e.g. `https://skybound-auth.onrender.com`)
5. After deploy, run the migration **once**:
   ```
   # In Render dashboard → your service → Shell
   npm run migrate
   ```

### Option B — Manual

1. Create a new **Web Service** on Render
   - Environment: `Node`
   - Build: `npm install`
   - Start: `npm start`
2. Create a **PostgreSQL** database on Render (free)
3. Add environment variables (see `.env.example`):
   - `DATABASE_URL` — copy from the Render DB dashboard
   - `SESSION_SECRET` — run `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` locally
   - `BASE_URL` — your `https://xxxx.onrender.com` URL
   - `NODE_ENV=production`
4. Deploy, then run `npm run migrate` once in the Shell tab

---

## API Reference

### OAuth2 Flow

```
1. Redirect user to:
   GET /oauth/authorize
     ?response_type=code
     &client_id=sky_YOUR_CLIENT_ID
     &redirect_uri=https://yourapp.com/callback
     &scope=openid profile
     &state=CSRF_TOKEN
     &code_challenge=BASE64URL(SHA256(verifier))   (optional PKCE)
     &code_challenge_method=S256

2. User logs in + approves → your redirect_uri receives ?code=xxx&state=yyy

3. Exchange code:
   POST /oauth/token
   grant_type=authorization_code
   &code=xxx
   &redirect_uri=https://yourapp.com/callback
   &client_id=sky_xxx
   &client_secret=sks_xxx
   &code_verifier=xxx   (if PKCE)

   Response: { access_token, refresh_token, token_type, expires_in, scope }

4. Get user info:
   GET /oauth/userinfo
   Authorization: Bearer ACCESS_TOKEN

   Response: { sub, username, display_name, avatar_url, bio, created_at }

5. Refresh:
   POST /oauth/token
   grant_type=refresh_token
   &refresh_token=xxx
   &client_id=sky_xxx
   &client_secret=sks_xxx
```

### All Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/authorize` | Authorization page |
| POST | `/oauth/authorize` | Submit consent |
| POST | `/oauth/token` | Token exchange & refresh |
| GET | `/oauth/userinfo` | Get user (Bearer token) |
| POST | `/oauth/revoke` | Revoke a token |
| GET | `/oauth/.well-known/openid-configuration` | OpenID discovery |
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login |
| POST | `/auth/logout` | Logout |
| GET | `/auth/me` | Current session |
| PATCH | `/auth/profile` | Update profile |
| GET | `/auth/authorizations` | List authorized apps |
| DELETE | `/auth/authorizations/:appId` | Revoke app |
| GET | `/apps` | List developer apps |
| POST | `/apps` | Register new app |
| GET | `/apps/:id` | Get app (with secret) |
| PATCH | `/apps/:id` | Update app |
| DELETE | `/apps/:id` | Delete app |
| POST | `/apps/:id/rotate-secret` | New client secret |
| GET | `/health` | Health check |

---

## Adding "Login with Skybound" to your site

### Register your app
1. Create a Skybound account at your deployment URL
2. Dashboard → My Apps → New App
3. Add your redirect URI(s)
4. Copy your `client_id` and `client_secret`

### Example button (HTML)
```html
<a href="https://skybound-auth.onrender.com/oauth/authorize
  ?response_type=code
  &client_id=sky_YOUR_ID
  &redirect_uri=https://yoursite.com/auth/callback
  &scope=openid%20profile
  &state=RANDOM">
  Login with Skybound
</a>
```

### Example callback handler (Node.js/Express)
```js
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  // verify state matches what you stored

  const resp = await fetch('https://skybound-auth.onrender.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://yoursite.com/auth/callback',
      client_id: process.env.SKYBOUND_CLIENT_ID,
      client_secret: process.env.SKYBOUND_CLIENT_SECRET,
    })
  });
  const { access_token } = await resp.json();

  const user = await fetch('https://skybound-auth.onrender.com/oauth/userinfo', {
    headers: { Authorization: `Bearer ${access_token}` }
  }).then(r => r.json());

  // user = { sub, username, display_name, avatar_url, ... }
  req.session.user = user;
  res.redirect('/dashboard');
});
```

---

## Scopes

| Scope | Data returned |
|-------|--------------|
| `openid` | `sub` (UUID) only |
| `profile` | `username`, `display_name`, `avatar_url`, `bio`, `created_at` |

---

## Notes on Render free tier

- Free web services spin down after 15 min of inactivity (cold start ~30s)
- Free PostgreSQL has a 1GB storage limit and expires after 90 days — upgrade or use Supabase/Neon for persistent free DB
- Session data is in-memory (lost on restart) — this is fine; users just re-login
- No email = no password reset; users must contact admin to reset passwords
