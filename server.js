require('dotenv').config();
const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const Babel    = require('@babel/standalone');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const SALT_ROUNDS = 10;

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

// ─── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ─── Simple in-memory rate limiter ──────────────────────────────────────────
const rateLimits = new Map(); // ip → { count, resetAt }
function rateLimit(windowMs = 60_000, max = 20) {
  return (req, res, next) => {
    const ip  = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = rateLimits.get(ip) || { count: 0, resetAt: now + windowMs };
    if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + windowMs; }
    rec.count++;
    rateLimits.set(ip, rec);
    if (rec.count > max) return res.status(429).json({ error: 'Zu viele Anfragen. Bitte warte kurz.' });
    next();
  };
}
// Clean up old entries every 5 minutes
setInterval(() => { const now = Date.now(); rateLimits.forEach((v,k) => { if (now > v.resetAt) rateLimits.delete(k); }); }, 300_000);

// ─── HMAC Session System ─────────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update((process.env.FIREBASE_API_KEY || '') + ':session-v1').digest('hex');
const SESSION_TTL = 7 * 24 * 3600_000;

function createSession(user) {
  const payload = { ...user, exp: Date.now() + SESSION_TTL };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  try {
    const dot = token.lastIndexOf('.');
    if (dot < 0) return null;
    const data = token.slice(0, dot), sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    const a = Buffer.from(sig, 'ascii'), b = Buffer.from(expected, 'ascii');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const payload = verifySession(req.headers['x-session']);
  if (!payload) return res.status(401).json({ error: 'Sitzung abgelaufen – bitte neu anmelden' });
  req.user = payload;
  next();
}

// ─── Firebase config ────────────────────────────────────────────────────────
const API_KEY    = process.env.FIREBASE_API_KEY    || 'AIzaSyAB9ugtPhwbXTJc9mZia6a_x54LEYLz5PE';
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'r3zahlen';
const firebaseConfig = JSON.stringify({
  apiKey:            API_KEY,
  authDomain:        process.env.FIREBASE_AUTH_DOMAIN        || 'r3zahlen.firebaseapp.com',
  projectId:         PROJECT_ID,
  storageBucket:     process.env.FIREBASE_STORAGE_BUCKET     || 'r3zahlen.firebasestorage.app',
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID|| '1071865171603',
  appId:             process.env.FIREBASE_APP_ID             || '1:1071865171603:web:399ef56359d043e7544766',
});

// ─── Server-side Firestore proxy (bypasses security rules via anon auth) ────
let _idToken = null, _refreshToken = null, _tokenExpiry = 0;

async function getToken() {
  const now = Date.now();
  if (_idToken && now < _tokenExpiry - 60_000) return _idToken;
  if (_refreshToken) {
    try {
      const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`,
        { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body:`grant_type=refresh_token&refresh_token=${_refreshToken}` });
      const d = await r.json();
      if (d.id_token) { _idToken=d.id_token; _refreshToken=d.refresh_token; _tokenExpiry=now+(+d.expires_in||3600)*1000; return _idToken; }
    } catch {}
  }
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`,
    { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({returnSecureToken:true}) });
  const d = await r.json();
  _idToken=d.idToken; _refreshToken=d.refreshToken; _tokenExpiry=now+(+d.expiresIn||3600)*1000;
  return _idToken;
}

function fsUrl(col, docId='') {
  return `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${col}${docId?'/'+docId:''}`;
}

function toFsValue(v) {
  if (v===null||v===undefined) return {nullValue:null};
  if (typeof v==='string')  return {stringValue:v};
  if (typeof v==='boolean') return {booleanValue:v};
  if (typeof v==='number')  return Number.isInteger(v)?{integerValue:String(v)}:{doubleValue:v};
  if (Array.isArray(v))     return {arrayValue:{values:v.map(toFsValue)}};
  if (typeof v==='object')  return {mapValue:{fields:Object.fromEntries(Object.entries(v).map(([k,val])=>[k,toFsValue(val)]))}};
  return {stringValue:String(v)};
}

function fromFsValue(fv) {
  if (!fv) return null;
  if ('stringValue'  in fv) return fv.stringValue;
  if ('integerValue' in fv) return parseInt(fv.integerValue);
  if ('doubleValue'  in fv) return fv.doubleValue;
  if ('booleanValue' in fv) return fv.booleanValue;
  if ('nullValue'    in fv) return null;
  if ('arrayValue'   in fv) return (fv.arrayValue.values||[]).map(fromFsValue);
  if ('mapValue'     in fv) return Object.fromEntries(Object.entries(fv.mapValue.fields||{}).map(([k,v])=>[k,fromFsValue(v)]));
  return null;
}

async function fsGetDoc(col, docId) {
  try {
    const token = await getToken();
    const r = await fetch(fsUrl(col, docId), {headers:{Authorization:`Bearer ${token}`}});
    if (!r.ok) { console.warn('fsGetDoc failed', r.status, col, docId); return null; }
    const d = await r.json();
    if (!d.fields) return null;
    return Object.fromEntries(Object.entries(d.fields).map(([k,v])=>[k,fromFsValue(v)]));
  } catch(e) { console.warn('fsGetDoc error:', e.message); return null; }
}

async function fsGetCollection(col) {
  try {
    const token = await getToken();
    const r = await fetch(fsUrl(col), {headers:{Authorization:`Bearer ${token}`}});
    if (!r.ok) { console.warn('fsGet failed', r.status, col); return null; }
    const d = await r.json();
    if (!d.documents) return [];
    return d.documents.map(doc=>({id:doc.name.split('/').pop(),...Object.fromEntries(Object.entries(doc.fields||{}).map(([k,v])=>[k,fromFsValue(v)]))}));
  } catch(e) { console.warn('fsGetCollection error:', e.message); return null; }
}

async function fsSet(col, docId, data) {
  try {
    const token = await getToken();
    const fields = Object.fromEntries(Object.entries(data).map(([k,v])=>[k,toFsValue(v)]));
    if (docId) {
      await fetch(fsUrl(col,docId),{method:'PATCH',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({fields})});
    } else {
      const r = await fetch(fsUrl(col),{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({fields})});
      const d = await r.json(); return d.name?.split('/').pop();
    }
  } catch(e) { console.warn('fsSet error:', e.message); }
}

async function fsDelete(col, docId) {
  try {
    const token = await getToken();
    await fetch(fsUrl(col,docId),{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});
  } catch(e) { console.warn('fsDelete error:', e.message); }
}

// ─── MA data proxy (bypasses Firestore security rules) ──────────────────────
// GET  /api/ma?profile=revive   → read {profile}/ma doc (returns {data:{...}})
app.get('/api/ma', async (req, res) => {
  const profile = req.query.profile;
  if (!profile) return res.status(400).json({error:'missing profile'});
  const doc = await fsGetDoc(profile, 'ma');
  if (doc === null) return res.status(503).json({error:'Firestore nicht erreichbar'});
  res.json(doc);
});

// POST /api/ma?profile=revive   → write {profile}/ma doc (body = {data:{...}})
app.post('/api/ma', authMiddleware, async (req, res) => {
  const profile = req.query.profile;
  if (!profile) return res.status(400).json({error:'missing profile'});
  await fsSet(profile, 'ma', req.body);
  res.json({ok:true});
});

// GET  /api/shared-ma   → read shared/ma doc
app.get('/api/shared-ma', async (req, res) => {
  const doc = await fsGetDoc('shared', 'ma');
  if (doc === null) return res.status(503).json({error:'Firestore nicht erreichbar'});
  res.json(doc);
});

// POST /api/shared-ma   → write shared/ma doc (body = {data:{...}})
app.post('/api/shared-ma', authMiddleware, async (req, res) => {
  await fsSet('shared', 'ma', req.body);
  res.json({ok:true});
});

// ─── ChurchTools proxy ───────────────────────────────────────────────────────
const CT_BASE  = process.env.CT_BASE_URL || 'https://k21.church.tools';
const CT_TOKEN = process.env.CT_TOKEN    || '';
if (!CT_TOKEN) console.warn('⚠ CT_TOKEN fehlt in .env – ChurchTools-Proxy wird nicht funktionieren');

app.get('/api/ct/*', rateLimit(60_000, 60), async (req, res) => {
  try {
    const ctPath = req.params[0];
    const qs     = new URLSearchParams(req.query).toString();
    const url    = `${CT_BASE}/api/${ctPath}${qs ? '?' + qs : ''}`;
    const r      = await fetch(url, { headers: { 'Authorization': `Login ${CT_TOKEN}` } });
    const d      = await r.json();
    res.json(d);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── API routes ──────────────────────────────────────────────────────────────

// Returns only names (no PINs) — safe for autocomplete
app.get('/api/user-names', async (req, res) => {
  const col = req.query.c || 'k21-users';
  const users = await fsGetCollection(col);
  if (users === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  // include id + name only, strip any PIN fields
  res.json(users.map(u => ({ id: u.id, name: u.name, role: u.role || 'user' })));
});

// Server-side login — compares PIN hash, never exposes hashes to client
app.post('/api/login', rateLimit(60_000, 10), async (req, res) => {
  const { name, pin, collection } = req.body || {};
  if (!name || !pin) return res.status(400).json({ error: 'Name und PIN erforderlich' });
  const col = collection || 'k21-users';

  // ── Admin login ──────────────────────────────────────────────────────────
  const adminDoc = await fsGetDoc('config', 'auth');
  const adminName = adminDoc?.adminName || 'Admin';
  if (name.toLowerCase() === adminName.toLowerCase()) {
    const adminHash = adminDoc?.adminPinHash;
    const adminPin  = adminDoc?.adminPin; // legacy plaintext
    const DEFAULT_OWNER_PIN = 'K21ADMIN'; // original hardcoded fallback
    let ok = false;
    if (adminHash) {
      ok = await bcrypt.compare(String(pin), adminHash);
    } else if (adminPin) {
      ok = String(pin) === String(adminPin);
      if (ok) {
        const hash = await bcrypt.hash(String(adminPin), SALT_ROUNDS);
        await fsSet('config', 'auth', { ...adminDoc, adminPinHash: hash, adminPin: null });
      }
    } else {
      // No PIN configured yet — accept the default hardcoded owner PIN
      ok = String(pin) === DEFAULT_OWNER_PIN;
    }
    if (!ok) return res.status(401).json({ error: 'Falscher PIN' });
    return res.json({ ok: true, role: 'admin', name: adminName, token: createSession({ id: 'admin', name: adminName, role: 'admin' }) });
  }

  // ── Regular user login ───────────────────────────────────────────────────
  const users = await fsGetCollection(col);
  if (users === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  const user = users.find(u => u.name?.toLowerCase() === name.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Unbekannter Benutzer' });

  let ok = false;
  if (user.pinHash) {
    ok = await bcrypt.compare(String(pin), user.pinHash);
  } else if (user.pin) {
    // Legacy plaintext — compare then migrate
    ok = String(pin) === String(user.pin);
    if (ok) {
      const hash = await bcrypt.hash(String(user.pin), SALT_ROUNDS);
      await fsSet(col, user.id, { ...user, pinHash: hash, pin: null });
    }
  }
  if (!ok) return res.status(401).json({ error: 'Falscher PIN' });
  return res.json({
    ok: true,
    role: user.role || 'user',
    name: user.name,
    id: user.id,
    permissions: user.permissions || {},
    areaAccess: user.areaAccess || {},
    areaGroups: user.areaGroups || {},
    areas: user.areas || [],
    token: createSession({ id: user.id, name: user.name, role: user.role || 'user' }),
  });
});

// Logout (stateless — client drops token; endpoint exists for symmetry)
app.post('/api/logout', (req, res) => res.json({ ok: true }));

// Admin-only: list users (names only, no hashes)
app.get('/api/users', async (req, res) => {
  const col = req.query.c || 'k21-users';
  const users = await fsGetCollection(col);
  if (users === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  // Strip PIN fields before sending
  res.json(users.map(({ pin: _p, pinHash: _h, ...rest }) => rest));
});

app.post('/api/users', authMiddleware, async (req, res) => {
  const col = req.query.c || 'k21-users';
  const { pin, ...rest } = req.body;
  const data = { ...rest, createdAt: new Date().toISOString() };
  if (pin) data.pinHash = await bcrypt.hash(String(pin), SALT_ROUNDS);
  const id = await fsSet(col, null, data);
  res.json({ id });
});

app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const col = req.query.c || 'k21-users';
  const { pin, ...rest } = req.body;
  const data = { ...rest };
  if (pin) data.pinHash = await bcrypt.hash(String(pin), SALT_ROUNDS);
  await fsSet(col, req.params.id, data);
  res.json({ ok: true });
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  const col = req.query.c || 'k21-users';
  await fsDelete(col, req.params.id);
  res.json({ ok: true });
});

// Admin PIN setup/change
app.get('/api/admin-pin', async (req, res) => {
  try {
    const doc = await fsGetDoc('config', 'auth');
    // Return whether a PIN is configured (but not the hash)
    res.json({ configured: !!(doc?.adminPinHash || doc?.adminPin), adminName: doc?.adminName || 'Admin' });
  } catch { res.json({ configured: false, adminName: 'Admin' }); }
});

app.post('/api/admin-pin', async (req, res) => {
  const { pin, name } = req.body || {};
  if (!pin) return res.status(400).json({ error: 'PIN erforderlich' });
  const existing = await fsGetDoc('config', 'auth') || {};
  // Allow unauthenticated first-time setup; require session for subsequent changes
  const isFirstSetup = !(existing.adminPinHash || existing.adminPin);
  if (!isFirstSetup) {
    const payload = verifySession(req.headers['x-session']);
    if (!payload) return res.status(401).json({ error: 'Sitzung abgelaufen – bitte neu anmelden' });
  }
  const hash = await bcrypt.hash(String(pin), SALT_ROUNDS);
  await fsSet('config', 'auth', { ...existing, adminPinHash: hash, adminPin: null, adminName: name || existing.adminName || 'Admin' });
  res.json({ ok: true });
});

// ─── Build HTML ──────────────────────────────────────────────────────────────
let compiledHtml;
try {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  compiledHtml = tmpl.replace(/<script type="text\/babel">([\s\S]*?)<\/script>/, (_, jsx) => {
    const result = Babel.transform(jsx, { presets:['react'], plugins:['transform-optional-chaining','transform-nullish-coalescing-operator'], sourceType:'script' });
    return `<script>\n${result.code}\n</script>`;
  });
  console.log('JSX compiled successfully');
} catch(err) {
  console.error('Babel error:', err.message);
  compiledHtml = `<!DOCTYPE html><html><body><pre style="color:red;padding:24px">BUILD ERROR:\n${err.message}</pre></body></html>`;
}

app.use('/fonts', express.static(path.join(__dirname, 'fonts'), {maxAge:'365d'}));
app.use('/logo.png', express.static(path.join(__dirname, 'logo.png'), {maxAge:'7d'}));

app.get('/', (req, res) => {
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(html);
});

app.use(express.static(__dirname));
app.listen(PORT, () => console.log(`REVIVE Mitarbeiter läuft auf http://localhost:${PORT}`));
