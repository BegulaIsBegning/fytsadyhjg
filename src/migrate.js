// src/migrate.js — Run once to set up the DB schema
const { pool } = require('./db');

async function migrate() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(32) UNIQUE NOT NULL,
        display_name VARCHAR(64),
        password_hash TEXT NOT NULL,
        avatar_url TEXT,
        bio TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // OAuth2 applications (registered by developers)
    await client.query(`
      CREATE TABLE IF NOT EXISTS oauth_apps (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(64) NOT NULL,
        description TEXT,
        client_id VARCHAR(64) UNIQUE NOT NULL,
        client_secret VARCHAR(128) NOT NULL,
        redirect_uris TEXT[] NOT NULL,
        scopes TEXT[] DEFAULT ARRAY['profile'],
        logo_url TEXT,
        website TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Authorization codes (short-lived, exchanged for tokens)
    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_codes (
        code VARCHAR(128) PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        app_id UUID REFERENCES oauth_apps(id) ON DELETE CASCADE,
        scopes TEXT[],
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT,
        code_challenge_method VARCHAR(10),
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN DEFAULT FALSE
      );
    `);

    // Access tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS access_tokens (
        token VARCHAR(256) PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        app_id UUID REFERENCES oauth_apps(id) ON DELETE CASCADE,
        scopes TEXT[],
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Refresh tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token VARCHAR(256) PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        app_id UUID REFERENCES oauth_apps(id) ON DELETE CASCADE,
        scopes TEXT[],
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // User sessions (for the Skybound login UI)
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid VARCHAR(255) PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMPTZ NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);
    `);

    // App authorizations (which users have approved which apps)
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_authorizations (
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        app_id UUID REFERENCES oauth_apps(id) ON DELETE CASCADE,
        scopes TEXT[],
        granted_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (user_id, app_id)
      );
    `);

    await client.query('COMMIT');
    console.log('✅ Migration complete');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
