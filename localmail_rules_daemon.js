#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════
// LocalMail Graph Rules Daemon
// ───────────────────────────────────────────────────────────────────────
// Reads tokens + rules directly from admin.db (same volume as admin-srv).
// No JSON files needed. No HTTP auth round-trips.
// Polls every POLL_INTERVAL_MS, applies Graph Rules to all admin accounts.
// Token is auto-refreshed silently — 90-day sliding window.
//
// SETUP:
//   Same Docker image as admin-srv (better-sqlite3 already installed).
//   Set DATA_DIR=/app/data (done in docker-compose.yml).
//   That's it — rules sync automatically from the app.
//
// ENV:
//   DATA_DIR          path to folder containing admin.db  [default: cwd]
//   POLL_INTERVAL_MS  poll frequency in ms                [default: 60000]
// ═══════════════════════════════════════════════════════════════════════

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DATA_DIR         = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : process.cwd();
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS) || 60_000;
const DB_PATH          = path.join(DATA_DIR, 'admin.db');
const SEEN_FILE        = path.join(DATA_DIR, 'gr_seen.json');

const CLIENT_ID  = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const TOKEN_URL  = 'https://login.microsoftonline.com/common/oauth2/token';

// ── Logging ───────────────────────────────────────────────────────────
const L = {
  ts:   () => new Date().toLocaleTimeString(),
  info: (...a) => console.log (`[${L.ts()}] ℹ`, ...a),
  ok:   (...a) => console.log (`[${L.ts()}] ✅`, ...a),
  warn: (...a) => console.warn(`[${L.ts()}] ⚠`, ...a),
  err:  (...a) => console.error(`[${L.ts()}] ❌`, ...a),
  rule: (...a) => console.log (`[${L.ts()}] ⚡`, ...a),
};

// ── DB ────────────────────────────────────────────────────────────────
let Database;
try { Database = require('better-sqlite3'); }
catch { L.err('better-sqlite3 not found — is this the right image?'); process.exit(1); }

let db;
function openDb() {
  if (db) return db;
  if (!fs.existsSync(DB_PATH)) { L.warn('admin.db not found yet at', DB_PATH, '— waiting…'); return null; }
  db = new Database(DB_PATH, { readonly: false });
  db.pragma('journal_mode = WAL');
  L.ok('Opened admin.db');
  return db;
}

// ── HTTP helpers ──────────────────────────────────────────────────────
function httpPost(url, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString(), u = new URL(url);
    const req = https.request({ hostname:u.hostname, path:u.pathname, method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)} },
      res => { let raw=''; res.on('data',c=>raw+=c); res.on('end',()=>{ try{resolve(JSON.parse(raw));}catch{reject(new Error('Bad JSON'));} }); });
    req.on('error', reject); req.write(body); req.end();
  });
}
function graphReq(method, path, token, body) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname:'graph.microsoft.com', path:'/v1.0'+path, method,
      headers:{ Authorization:'Bearer '+token, Accept:'application/json', ...(body?{'Content-Type':'application/json'}:{}) }
    }, res => { let raw=''; res.on('data',c=>raw+=c); res.on('end',()=>{ if(!raw.trim()){resolve({});return;} try{resolve(JSON.parse(raw));}catch{reject(new Error('Bad JSON'));} }); });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Token management (reads + writes directly to DB rows) ─────────────
// Returns { access_token, rowId } — refreshing in-DB if needed
async function getValidToken(row) {
  const d = openDb();
  if (!d) return null;

  const needsRefresh = !row.expires_at || Date.now() > new Date(row.expires_at).getTime() - 120_000;
  if (!needsRefresh) return { access_token: row.access_token, rowId: row.id };

  if (!row.refresh_token) { L.warn(`Token id=${row.id} (${row.email}) expired, no refresh_token — skipping`); return null; }

  L.info(`Refreshing token for ${row.email}…`);
  const res = await httpPost(TOKEN_URL, {
    grant_type: 'refresh_token', client_id: CLIENT_ID,
    refresh_token: row.refresh_token, resource: 'https://graph.microsoft.com', scope: 'offline_access',
  });
  if (res.error) { L.err(`Refresh failed for ${row.email}: ${res.error}`); return null; }

  const expiresAt = new Date(Date.now() + Number(res.expires_in||3600)*1000).toISOString();
  d.prepare(`UPDATE m365_tokens SET access_token=?,refresh_token=?,expires_at=?,refreshed_at=datetime('now') WHERE id=?`)
   .run(res.access_token, res.refresh_token||row.refresh_token, expiresAt, row.id);
  L.ok(`Token refreshed for ${row.email}, valid until ${expiresAt}`);
  return { access_token: res.access_token, rowId: row.id };
}

// ── Rules engine ──────────────────────────────────────────────────────
function msgMatch(msg, rule) {
  const conds = rule.conditions || [];
  if (!conds.length) return false;
  const check = c => {
    let hay = '';
    switch(c.field) {
      case 'subject':    hay = msg.subject || ''; break;
      case 'from_email': hay = msg.from?.emailAddress?.address || ''; break;
      case 'from_name':  hay = msg.from?.emailAddress?.name    || ''; break;
      case 'body':       hay = msg.bodyPreview || ''; break;
      case 'attachment': hay = (msg.attachments||[]).map(a=>a.name||'').join(' '); break;
    }
    hay = hay.toLowerCase();
    const val = (c.value||'').toLowerCase();
    switch(c.op) {
      case 'contains':     return hay.includes(val);
      case 'not_contains': return !hay.includes(val);
      case 'starts_with':  return hay.startsWith(val);
      case 'ends_with':    return hay.endsWith(val);
      case 'equals':       return hay === val;
      case 'regex':        try{return new RegExp(c.value,'i').test(hay);}catch{return false;}
      default: return false;
    }
  };
  return rule.conditionMode === 'any' ? conds.some(check) : conds.every(check);
}

async function execActions(msg, rule, token) {
  for (const act of (rule.actions||[])) {
    try {
      switch(act.type) {
        case 'delete':    await graphReq('POST', `/me/messages/${msg.id}/move`, token, {destinationId:'deleteditems'}); L.rule(`[${rule.name}] DELETE "${msg.subject}"`); break;
        case 'archive': {
          const fl = await graphReq('GET', '/me/mailFolders?$top=50', token);
          const arch = (fl.value||[]).find(f=>f.displayName==='Archive'||f.wellKnownName==='archive');
          await graphReq('POST', `/me/messages/${msg.id}/move`, token, {destinationId:arch?.id||'archive'});
          L.rule(`[${rule.name}] ARCHIVE "${msg.subject}"`); break;
        }
        case 'move':      if(act.param){await graphReq('POST', `/me/messages/${msg.id}/move`, token, {destinationId:act.param}); L.rule(`[${rule.name}] MOVE "${msg.subject}"`);} break;
        case 'mark_read': await graphReq('PATCH', `/me/messages/${msg.id}`, token, {isRead:true}); L.rule(`[${rule.name}] MARK READ "${msg.subject}"`); break;
        case 'mark_unread': await graphReq('PATCH', `/me/messages/${msg.id}`, token, {isRead:false}); L.rule(`[${rule.name}] MARK UNREAD "${msg.subject}"`); break;
        case 'flag':      await graphReq('PATCH', `/me/messages/${msg.id}`, token, {flag:{flagStatus:'flagged'}}); L.rule(`[${rule.name}] FLAG "${msg.subject}"`); break;
        case 'forward':   if(act.param){await graphReq('POST', `/me/messages/${msg.id}/forward`, token, {toRecipients:[{emailAddress:{address:act.param}}]}); L.rule(`[${rule.name}] FORWARD "${msg.subject}" → ${act.param}`);} break;
        case 'reply':     if(act.param){
          const replyBody = { comment: act.param };
          if (act.replySubject) replyBody.message = { subject: act.replySubject };
          await graphReq('POST', `/me/messages/${msg.id}/reply`, token, replyBody);
          L.rule(`[${rule.name}] REPLY "${msg.subject}"`);
        } break;
        case 'purge': {
          // Move to Deleted Items first (if not already), then permanently delete
          try { await graphReq('POST', `/me/messages/${msg.id}/move`, token, {destinationId:'deleteditems'}); } catch {}
          // Wait briefly then delete permanently
          await new Promise(r=>setTimeout(r,800));
          await graphReq('DELETE', `/me/messages/${msg.id}`, token, null);
          L.rule(`[${rule.name}] PURGE "${msg.subject}"`);
          break;
        }
        case 'filter': {
          const fp = act.filterParam || '';
          if (fp === 'junk')         await graphReq('POST', `/me/messages/${msg.id}/move`, token, {destinationId:'junkemail'});
          else if (fp === 'low')     await graphReq('PATCH', `/me/messages/${msg.id}`, token, {importance:'low'});
          else if (fp === 'high')    await graphReq('PATCH', `/me/messages/${msg.id}`, token, {importance:'high'});
          else if (fp.startsWith('category_')) {
            const colour = fp.replace('category_','');
            await graphReq('PATCH', `/me/messages/${msg.id}`, token, {categories:[colour]});
          }
          L.rule(`[${rule.name}] FILTER(${fp}) "${msg.subject}"`);
          break;
        }
      }
    } catch(e) { L.err(`[${rule.name}] action "${act.type}" failed: ${e.message}`); }
  }
}


// ── Folder + full-message load helpers (mirrors main app) ────────────
// Mirrors app's loadAllFoldersRecursive exactly:
// returns a flat array with id, displayName, wellKnownName,
// childFolderCount, children[], depth, parentId.
// Used by poll loop to resolve watchFolders by ID.
async function loadAllFolders(token) {
  const allFolders = [], folderMap = {};

  async function fetchChildrenOf(parentId, depth) {
    let skip = 0;
    while (true) {
      const res = await graphReq('GET',
        `/me/mailFolders/${encodeURIComponent(parentId)}/childFolders` +
        `?$top=100&$skip=${skip}&$select=id,displayName,unreadItemCount,totalItemCount,childFolderCount`,
        token).catch(() => null);
      if (!res) break;
      const items = res.value || [];
      for (const f of items) {
        const node = {
          id: f.id, name: f.displayName,
          unreadCount: f.unreadItemCount || 0,
          totalCount:  f.totalItemCount  || 0,
          childFolderCount: f.childFolderCount || 0,
          children: [], depth, parentId,
        };
        allFolders.push(node);
        folderMap[f.id] = node;
        const parent = folderMap[parentId];
        if (parent) parent.children.push(node);
        if (f.childFolderCount > 0) await fetchChildrenOf(f.id, depth + 1);
      }
      if (items.length < 100) break;
      skip += 100;
    }
  }

  // Top-level folders
  let skip = 0;
  while (true) {
    const res = await graphReq('GET',
      `/me/mailFolders?$top=100&$skip=${skip}&$select=id,displayName,unreadItemCount,totalItemCount,childFolderCount`,
      token).catch(() => null);
    if (!res) break;
    for (const f of (res.value||[])) {
      const node = { id:f.id, name:f.displayName, unreadCount:f.unreadItemCount||0, totalCount:f.totalItemCount||0, childFolderCount:f.childFolderCount||0, children:[], depth:0, parentId:null };
      allFolders.push(node);
      folderMap[f.id] = node;
    }
    if ((res.value||[]).length < 100) break;
    skip += 100;
  }

  // Recurse into all top-level folders with children
  for (const node of allFolders.filter(n => n.depth === 0 && n.childFolderCount > 0)) {
    await fetchChildrenOf(node.id, 1);
  }

  return { all: allFolders, map: folderMap };
}

async function loadAllMessages(token, folderId, maxPages=10) {
  const msgs = [];
  let path = `/me/mailFolders/${folderId}/messages?$top=50&$orderby=receivedDateTime%20desc&$select=id,subject,from,bodyPreview,hasAttachments,isRead,receivedDateTime`;
  let pages = 0;
  while (path && pages < maxPages) {
    const res = await graphReq('GET', path, token);
    msgs.push(...(res.value||[]));
    pages++;
    if (res['@odata.nextLink']) {
      const u = new URL(res['@odata.nextLink']);
      path = u.pathname.replace('/v1.0','') + u.search;
    } else path = null;
  }
  return msgs;
}

// ── Telegram notification helper ─────────────────────────────
const https_tg = require('https');
function sendTelegram(token, chatId, text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' });
    const req  = https_tg.request({
      hostname:'api.telegram.org', path:`/bot${token}/sendMessage`, method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)},
    }, res => {
      let raw=''; res.on('data',c=>raw+=c);
      res.on('end',()=>{ try{const d=JSON.parse(raw);d.ok?resolve(d):reject(new Error(d.description||'Tg error'));}catch{reject(new Error('Bad JSON'));} });
    });
    req.on('error',reject); req.write(body); req.end();
  });
}

function buildNotifText(rule, msg) {
  const tmpl = rule.notify_template || rule.notifyTemplate ||
    '📬 *New email from {{from_name}}*\n\n*From:* {{from_email}}\n*Subject:* {{subject}}\n*Preview:* {{preview}}\n\n_{{time}}_';
  const fromAddr = msg.from?.emailAddress?.address || '';
  const fromName = msg.from?.emailAddress?.name    || fromAddr;
  return tmpl
    .replace('{{from_name}}',  fromName)
    .replace('{{from_email}}', fromAddr)
    .replace('{{subject}}',    msg.subject    || '(no subject)')
    .replace('{{preview}}',    (msg.bodyPreview||'').slice(0,120))
    .replace('{{time}}',       msg.receivedDateTime ? new Date(msg.receivedDateTime).toLocaleString() : new Date().toLocaleString());
}

// ── Seen-messages tracker ─────────────────────────────────────────────
// Key: "adminId:msgId" so different accounts don't collide
let seenIds = new Set();
function loadSeen() { try { seenIds = new Set(JSON.parse(fs.readFileSync(SEEN_FILE,'utf8'))); } catch { seenIds = new Set(); } }
function markSeen(keys) {
  keys.forEach(k => seenIds.add(k));
  if (seenIds.size > 5000) seenIds = new Set([...seenIds].slice(-5000));
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify([...seenIds])); } catch {}
}

// ── Main poll ─────────────────────────────────────────────────────────
async function poll() {
  const d = openDb();
  if (!d) return;

  // Get all token rows
  const tokenRows = d.prepare('SELECT id, admin_id, email, name, access_token, refresh_token, expires_at FROM m365_tokens').all();
  if (!tokenRows.length) { L.info('No tokens in DB yet'); return; }

  for (const row of tokenRows) {
    try {
      // Get valid (possibly refreshed) token
      const tokenResult = await getValidToken(row);
      if (!tokenResult) continue;
      const { access_token } = tokenResult;

      // Load enabled rules for this admin
      const rules = d.prepare('SELECT * FROM graph_rules WHERE admin_id=? AND enabled=1 ORDER BY id ASC').all(row.admin_id)
        .map(r => ({...r, enabled:true, conditions:JSON.parse(r.conditions||'[]'), actions:JSON.parse(r.actions||'[]'), watchFolders:JSON.parse(r.watch_folders||r.watchFolders||'[]')}));
      if (!rules.length) { L.info(`No enabled rules for ${row.email}`); continue; }

      // Load full folder tree (same logic as app) — resolves IDs, nested folders
      let folderMap = {};
      try {
        const { map } = await loadAllFolders(access_token);
        folderMap = map;
        L.info(`${row.email}: loaded ${Object.keys(map).length} folders`);
      } catch(e) { L.warn(`Could not load folders for ${row.email}: ${e.message}`); }

      // Resolve 'inbox' well-known to real ID
      const resolveId = (id) => {
        if (id !== 'inbox' && id !== 'archive' && id !== 'junkemail') return id;
        const match = Object.values(folderMap).find(f => f.name?.toLowerCase() === id || f.id === id);
        return match?.id || id;
      };

      // Collect unique folder IDs across all rules (skip 'existing'-only rules for real-time)
      const folderIds = new Set();
      for (const rule of rules) {
        if (rule.run_on === 'existing') continue;
        if (rule.run_on === 'folders' && rule.watchFolders.length) rule.watchFolders.forEach(id => folderIds.add(resolveId(id)));
        else folderIds.add('inbox');
      }
      if (!folderIds.size) { L.info(`No real-time folders for ${row.email}`); continue; }

      // Fetch messages from each relevant folder using loadAllMessages
      let allMsgs = [];
      for (const fid of folderIds) {
        try {
          const msgs = await loadAllMessages(access_token, fid, 3); // 3 pages = 150 messages per folder
          allMsgs = allMsgs.concat(msgs.map(m => ({...m, _sourceFolderId: fid})));
        } catch(e) { L.warn(`Could not fetch folder ${fid} for ${row.email}: ${e.message}`); }
      }

      // Filter to unseen messages
      const msgs = allMsgs.filter(m => !seenIds.has(`${row.admin_id}:${m.id}`));
      if (!msgs.length) { L.info(`No new messages for ${row.email}`); continue; }

      L.info(`${msgs.length} new message(s) for ${row.email}, checking ${rules.length} rule(s)`);
      let matched = 0;
      const ruleStats = {}; // rule_id → { match_count, last_run }

      for (const msg of msgs) {
        for (const rule of rules) {
          // Skip if rule is scoped to specific folders and this msg isn't from one
          if (rule.run_on === 'existing') continue;
          if (rule.run_on === 'folders' && rule.watchFolders.length) {
            if (!rule.watchFolders.includes(msg._sourceFolderId)) continue;
          }
          if (msgMatch(msg, rule)) {
            await execActions(msg, rule, access_token);
            matched++;
            if (!ruleStats[rule.rule_id]) ruleStats[rule.rule_id] = { match_count: rule.match_count, last_run: null };
            ruleStats[rule.rule_id].match_count++;
            ruleStats[rule.rule_id].last_run = new Date().toISOString();
            // ── Telegram notification ─────────────────────────
            const tok  = rule.notify_token  || rule.notifyToken  || '';
            const chat = rule.notify_chat   || rule.notifyChatId || '';
            if ((rule.notify || rule.notify_on_match) && tok && chat) {
              sendTelegram(tok, chat, buildNotifText(rule, msg))
                .then(() => L.rule(`[${rule.name}] 📲 TELEGRAM → "${msg.subject}"`))
                .catch(e  => L.warn(`[${rule.name}] Telegram failed: ${e.message}`));
            }
            break; // first matching rule wins
          }
        }
      }

      markSeen(msgs.map(m => `${row.admin_id}:${m.id}`));

      // Write match stats back to DB
      if (Object.keys(ruleStats).length) {
        const updateStats = d.prepare(`UPDATE graph_rules SET match_count=?,last_run=?,updated_at=datetime('now') WHERE admin_id=? AND rule_id=?`);
        d.transaction(stats => {
          for (const [ruleId, s] of Object.entries(stats)) updateStats.run(s.match_count, s.last_run, row.admin_id, ruleId);
        })(ruleStats);
        L.ok(`${matched} message(s) processed for ${row.email}`);
      } else {
        L.info(`No rules matched for ${row.email}`);
      }
    } catch(e) {
      L.err(`Error processing account ${row.email}: ${e.message}`);
    }
  }
}

// ── Startup ───────────────────────────────────────────────────────────
console.log('');
console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║  LocalMail Graph Rules Daemon                            ║');
console.log('║  Reads tokens + rules from admin.db — no browser needed  ║');
console.log('╚══════════════════════════════════════════════════════════╝');
console.log('');
L.info('Data dir   :', DATA_DIR);
L.info('DB path    :', DB_PATH);
L.info('Poll every :', POLL_INTERVAL_MS / 1000 + 's');
console.log('');

loadSeen();
poll().then(() => setInterval(poll, POLL_INTERVAL_MS));
process.on('SIGINT',  () => { L.info('Stopped.'); try{db?.close();}catch{} process.exit(0); });
process.on('SIGTERM', () => { L.info('Stopped.'); try{db?.close();}catch{} process.exit(0); });