const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const log = require('@vladmandic/pilogger');

const DEFAULT_DSN = process.env.DATABASE_URL || null;

function buildConnection() {
  if (DEFAULT_DSN) return { connectionString: DEFAULT_DSN };
  // Fallback to discrete env vars
  const host = process.env.PGHOST || 'localhost';
  const port = parseInt(process.env.PGPORT || '5432', 10);
  const user = process.env.PGUSER || 'stream';
  const password = process.env.PGPASSWORD || 'stream';
  const database = process.env.PGDATABASE || 'stream';
  return { host, port, user, password, database };
}

const pool = new Pool(buildConnection());

async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

async function init() {
  await query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`);

  await query(`CREATE TABLE IF NOT EXISTS server_config (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    http_port INTEGER NOT NULL DEFAULT 8000,
    https_port INTEGER NOT NULL DEFAULT 8001,
    encoder_port TEXT NOT NULL DEFAULT ':8002',
    ice_servers TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    webrtc_min_port INTEGER NOT NULL DEFAULT 32768,
    webrtc_max_port INTEGER NOT NULL DEFAULT 65535,
    retry_connect_sec INTEGER NOT NULL DEFAULT 10,
    start_stream_server BOOLEAN NOT NULL DEFAULT FALSE
  );`);

  await query(`CREATE TABLE IF NOT EXISTS streams (
    id SERIAL PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL,
    url TEXT DEFAULT '',
    status BOOLEAN NOT NULL DEFAULT TRUE,
    vod BOOLEAN NOT NULL DEFAULT FALSE,
    disable_audio BOOLEAN NOT NULL DEFAULT TRUE,
    debug BOOLEAN NOT NULL DEFAULT FALSE
  );`);

  // Seed data if empty
  const ucount = await query('SELECT COUNT(*)::int AS c FROM users');
  if ((ucount.rows[0].c || 0) === 0) {
    const passwordHash = bcrypt.hashSync(process.env.DEFAULT_ADMIN_PASSWORD || 'admin', 10);
    await query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [process.env.DEFAULT_ADMIN_USERNAME || 'admin', passwordHash]);
    log.state('db', 'seeded default admin user: admin/admin');
  }

  const scount = await query('SELECT COUNT(*)::int AS c FROM server_config');
  if ((scount.rows[0].c || 0) === 0) {
    // Try to load existing config.json as initial data
    let json = {};
    try {
      const file = path.join(process.cwd(), 'config.json');
      if (fs.existsSync(file)) json = JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch { /* ignore */ }
    const s = json.server || {};
    await query(
      `INSERT INTO server_config (id, http_port, https_port, encoder_port, ice_servers, webrtc_min_port, webrtc_max_port, retry_connect_sec, start_stream_server)
       VALUES (1,$1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        s.httpPort || 8000,
        s.httpsPort || 8001,
        s.encoderPort || ':8002',
        Array.isArray(s.iceServers) ? s.iceServers : [],
        s.webrtcMinPort || 32768,
        s.webrtcMaxPort || 65535,
        s.retryConnectSec || 10,
        !!s.startStreamServer,
      ],
    );
    // Seed streams by names if present
    if (json.streams) {
      const names = Object.keys(json.streams);
      for (const name of names) {
        const rec = json.streams[name] || {};
        await query(
          'INSERT INTO streams (uuid, url, status, vod, disable_audio, debug) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (uuid) DO NOTHING',
          [name, rec.url || '', rec.status ?? true, !!rec.VOD, !!rec.disableAudio, !!rec.debug],
        );
      }
    }
    log.state('db', 'seeded server_config and streams from config.json if present');
  }
}

async function getServerConfig() {
  const { rows } = await query('SELECT * FROM server_config WHERE id=1');
  return rows[0];
}

async function getStreamsMap() {
  const { rows } = await query('SELECT uuid, url, status, vod, disable_audio, debug FROM streams ORDER BY id');
  const map = {};
  for (const r of rows) {
    map[r.uuid] = {
      url: r.url,
      status: r.status,
      VOD: r.vod,
      disableAudio: r.disable_audio,
      debug: r.debug,
    };
  }
  return map;
}

async function getUserByUsername(username) {
  const { rows } = await query('SELECT * FROM users WHERE username=$1', [username]);
  return rows[0] || null;
}

module.exports = {
  pool,
  query,
  init,
  getServerConfig,
  getStreamsMap,
  getUserByUsername,
};
