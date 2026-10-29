'use strict';
/**
 * WebCraft Studio backend
 * - Authentication (email/password + Google ID token), JWT sessions
 * - Static-site hosting on Cloudflare Pages (publish / redeploy / unpublish)
 * - Optional AI website generation (Anthropic API)
 *
 * All secrets come from environment variables. Nothing is hardcoded.
 * Requires Node.js >= 22.13 (uses the built-in node:sqlite module).
 */
require('dotenv').config();
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/* ---------- Config ---------- */
const env = (k, d = '') => (process.env[k] || d).trim();
const PORT = Number(env('PORT', '8787'));
const JWT_SECRET = env('JWT_SECRET');
const ALLOWED_ORIGINS = env('ALLOWED_ORIGINS').split(',').map(s => s.trim()).filter(Boolean);
const GOOGLE_CLIENT_ID = env('GOOGLE_CLIENT_ID');
const CF_TOKEN = env('CLOUDFLARE_API_TOKEN');
const CF_ACCOUNT = env('CLOUDFLARE_ACCOUNT_ID');
const ANTHROPIC_KEY = env('ANTHROPIC_API_KEY');
const ANTHROPIC_MODEL = env('ANTHROPIC_MODEL', 'claude-sonnet-5-5');
const DB_PATH = env('DB_PATH', path.join(__dirname, 'data.sqlite'));
const MAX_SITES_PER_USER = Number(env('MAX_SITES_PER_USER', '10'));

if (JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be set and at least 32 characters long. Generate one with:\n  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  process.exit(1);
}
if (!ALLOWED_ORIGINS.length) {
  console.error('FATAL: ALLOWED_ORIGINS must list the origin(s) that host your index.html (comma separated).');
  process.exit(1);
}
const hostingReady = !!(CF_TOKEN && CF_ACCOUNT);
const googleReady = !!GOOGLE_CLIENT_ID;
const aiReady = !!ANTHROPIC_KEY;
let googleClient = null;
if (googleReady) { const { OAuth2Client } = require('google-auth-library'); googleClient = new OAuth2Client(GOOGLE_CLIENT_ID); }

/* ---------- Database ---------- */
const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT,
  google_sub TEXT UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  cf_project TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  deployed_at INTEGER NOT NULL,
  UNIQUE (user_id, project_id)
);`);
const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT id, email, name FROM users WHERE id = ?'),
  userByGoogle: db.prepare('SELECT * FROM users WHERE google_sub = ?'),
  insertUser: db.prepare('INSERT INTO users (email, name, password_hash, google_sub, created_at) VALUES (?, ?, ?, ?, ?)'),
  linkGoogle: db.prepare('UPDATE users SET google_sub = ? WHERE id = ?'),
  site: db.prepare('SELECT * FROM sites WHERE user_id = ? AND project_id = ?'),
  siteCount: db.prepare('SELECT COUNT(*) AS n FROM sites WHERE user_id = ?'),
  upsertSite: db.prepare(`INSERT INTO sites (user_id, project_id, cf_project, url, deployed_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, project_id) DO UPDATE SET url = excluded.url, deployed_at = excluded.deployed_at`),
  deleteSite: db.prepare('DELETE FROM sites WHERE user_id = ? AND project_id = ?')
};

/* ---------- App ---------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(env('TRUST_PROXY', '1')));
app.use(helmet());
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
app.use(express.json({ limit: '4mb' }));

const limiter = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Please try again later.' } });
app.use('/api/', limiter(60 * 1000, 120));
const authLimiter = limiter(15 * 60 * 1000, 20);
const deployLimiter = limiter(60 * 60 * 1000, 30);
const aiLimiter = limiter(60 * 60 * 1000, 20);

const fail = (res, status, error) => res.status(status).json({ error });
const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(err => {
  console.error(`[${new Date().toISOString()}] ${req.method} ${req.path}`, err && err.message);
  fail(res, 500, 'Internal server error.');
});

/* ---------- Auth helpers ---------- */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const signToken = user => jwt.sign({ sub: String(user.id) }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' });
const publicUser = u => ({ id: u.id, name: u.name, email: u.email });
function requireAuth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return fail(res, 401, 'Authentication required.');
  try {
    const p = jwt.verify(m[1], JWT_SECRET, { algorithms: ['HS256'] });
    const user = q.userById.get(Number(p.sub));
    if (!user) return fail(res, 401, 'Account not found.');
    req.user = user; next();
  } catch (e) { fail(res, 401, 'Session expired. Please log in again.'); }
}
// Constant-ish time login: always run a bcrypt compare even for unknown emails.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

/* ---------- Routes: health & auth ---------- */
app.get('/api/health', (req, res) => res.json({ ok: true, hosting: hostingReady, google: googleReady, ai: aiReady }));

app.post('/api/auth/register', authLimiter, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (!name || name.length > 60) return fail(res, 400, 'A valid name is required (max 60 characters).');
  if (!EMAIL_RE.test(email) || email.length > 120) return fail(res, 400, 'Enter a valid email address.');
  if (password.length < 8 || password.length > 128) return fail(res, 400, 'Password must be 8–128 characters.');
  if (q.userByEmail.get(email)) return fail(res, 409, 'An account with this email already exists.');
  const hash = await bcrypt.hash(password, 12);
  const r = q.insertUser.run(email, name, hash, null, Date.now());
  const user = { id: Number(r.lastInsertRowid), name, email };
  res.status(201).json({ token: signToken(user), user: publicUser(user) });
}));

app.post('/api/auth/login', authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  const row = q.userByEmail.get(email);
  const ok = await bcrypt.compare(password.slice(0, 128), row && row.password_hash ? row.password_hash : DUMMY_HASH);
  if (!row || !row.password_hash || !ok) return fail(res, 401, 'Incorrect email or password.');
  res.json({ token: signToken(row), user: publicUser(row) });
}));

app.post('/api/auth/google', authLimiter, wrap(async (req, res) => {
  if (!googleReady) return fail(res, 501, 'Google sign-in is not configured on the server.');
  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: String(req.body.credential || ''), audience: GOOGLE_CLIENT_ID });
    payload = ticket.getPayload();
  } catch (e) { return fail(res, 401, 'Google sign-in could not be verified.'); }
  if (!payload || !payload.sub || !payload.email || !payload.email_verified) return fail(res, 401, 'Google account email is not verified.');
  const email = payload.email.toLowerCase();
  let user = q.userByGoogle.get(payload.sub);
  if (!user) {
    const existing = q.userByEmail.get(email);
    if (existing) { q.linkGoogle.run(payload.sub, existing.id); user = existing; }
    else {
      const name = String(payload.name || email.split('@')[0]).slice(0, 60);
      const r = q.insertUser.run(email, name, null, payload.sub, Date.now());
      user = { id: Number(r.lastInsertRowid), name, email };
    }
  }
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

/* ---------- Hosting (Cloudflare Pages) ---------- */
const FILE_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._\-\/]{0,63}$/;
const MAX_FILES = 40, MAX_TOTAL_BYTES = 3 * 1024 * 1024;
function validateFiles(files) {
  if (!files || typeof files !== 'object' || Array.isArray(files)) return 'Invalid files payload.';
  const names = Object.keys(files);
  if (!names.length || names.length > MAX_FILES) return `A site must have between 1 and ${MAX_FILES} files.`;
  if (typeof files['index.html'] !== 'string' || !files['index.html'].trim()) return 'index.html is required.';
  let total = 0;
  for (const n of names) {
    if (!FILE_KEY_RE.test(n) || n.includes('..') || n.endsWith('/')) return `Invalid file name: ${n.slice(0, 40)}`;
    if (typeof files[n] !== 'string') return `File ${n} must be text.`;
    total += Buffer.byteLength(files[n]);
  }
  if (total > MAX_TOTAL_BYTES) return 'Site is too large (max 3 MB).';
  return '';
}
const cfProjectName = (userId, projectId) => 'wc-' + crypto.createHash('sha256').update(`${userId}:${projectId}`).digest('hex').slice(0, 24);

async function cf(method, apiPath, body) {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${CF_TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000)
  });
  let data = null; try { data = await res.json(); } catch (e) {}
  return { status: res.status, ok: res.ok && data && data.success !== false, data };
}
const cfError = d => (d && d.errors && d.errors[0] && d.errors[0].message) || 'Cloudflare request failed.';

function runWrangler(args, cwd) {
  return new Promise((resolve, reject) => {
    const bin = path.join(__dirname, 'node_modules', '.bin', process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler');
    execFile(bin, args, {
      cwd, timeout: 180000, maxBuffer: 5 * 1024 * 1024,
      env: { PATH: process.env.PATH, HOME: process.env.HOME || os.tmpdir(), CLOUDFLARE_API_TOKEN: CF_TOKEN, CLOUDFLARE_ACCOUNT_ID: CF_ACCOUNT, WRANGLER_SEND_METRICS: 'false', CI: '1' }
    }, (err, stdout, stderr) => err ? reject(new Error((stderr || err.message || '').slice(0, 400))) : resolve(stdout));
  });
}

app.post('/api/sites/publish', requireAuth, deployLimiter, wrap(async (req, res) => {
  if (!hostingReady) return fail(res, 501, 'Hosting backend not configured.');
  const projectId = String(req.body.projectId || '');
  if (!/^[A-Za-z0-9_\-]{3,64}$/.test(projectId)) return fail(res, 400, 'Invalid project id.');
  const bad = validateFiles(req.body.files); if (bad) return fail(res, 400, bad);

  const existing = q.site.get(req.user.id, projectId);
  if (!existing && q.siteCount.get(req.user.id).n >= MAX_SITES_PER_USER) return fail(res, 403, `Site limit reached (${MAX_SITES_PER_USER}). Unpublish a site first.`);
  const name = existing ? existing.cf_project : cfProjectName(req.user.id, projectId);

  // Create the Pages project if needed (409/8000002 = already exists).
  const created = await cf('POST', '/pages/projects', { name, production_branch: 'main' });
  let subdomain = created.ok && created.data.result && created.data.result.subdomain;
  if (!created.ok) {
    const code = created.data && created.data.errors && created.data.errors[0] && created.data.errors[0].code;
    if (created.status !== 409 && code !== 8000002) return fail(res, 502, `Hosting error: ${cfError(created.data)}`);
    const got = await cf('GET', `/pages/projects/${name}`);
    if (!got.ok) return fail(res, 502, `Hosting error: ${cfError(got.data)}`);
    subdomain = got.data.result && got.data.result.subdomain;
  }
  if (!subdomain) return fail(res, 502, 'Hosting error: no public URL was returned.');

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'wc-site-'));
  try {
    for (const [n, content] of Object.entries(req.body.files)) {
      const target = path.join(dir, n);
      if (!target.startsWith(dir + path.sep)) throw new Error('Unsafe path.');
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, content, 'utf8');
    }
    await runWrangler(['pages', 'deploy', dir, '--project-name', name, '--branch', 'main', '--commit-dirty=true'], __dirname);
  } catch (e) {
    console.error('Deploy failed:', e.message);
    return fail(res, 502, 'Deployment failed. Check server logs and Cloudflare credentials.');
  } finally { fs.rm(dir, { recursive: true, force: true }).catch(() => {}); }

  const url = `https://${subdomain}`;
  q.upsertSite.run(req.user.id, projectId, name, url, Date.now());
  res.json({ url, status: 'live', deployedAt: Date.now() });
}));

app.delete('/api/sites/:projectId', requireAuth, deployLimiter, wrap(async (req, res) => {
  if (!hostingReady) return fail(res, 501, 'Hosting backend not configured.');
  const site = q.site.get(req.user.id, String(req.params.projectId));
  if (!site) return res.json({ ok: true });
  const del = await cf('DELETE', `/pages/projects/${site.cf_project}`);
  if (!del.ok && del.status !== 404) return fail(res, 502, `Hosting error: ${cfError(del.data)}`);
  q.deleteSite.run(req.user.id, site.project_id);
  res.json({ ok: true });
}));

/* ---------- AI generation (optional) ---------- */
app.post('/api/ai/generate', requireAuth, aiLimiter, wrap(async (req, res) => {
  if (!aiReady) return fail(res, 501, 'AI backend not configured.');
  const prompt = String(req.body.prompt || '').trim().slice(0, 1500);
  const name = String(req.body.name || '').trim().slice(0, 60);
  const color = /^#[0-9a-f]{6}$/i.test(req.body.color || '') ? req.body.color : '#6d5dfc';
  if (prompt.length < 3) return fail(res, 400, 'Please describe the website.');
  const system = 'You generate small static websites. Reply with ONLY a JSON object (no markdown fences) of the form {"files":{"index.html":"...","style.css":"...","script.js":"..."}}. Rules: responsive, mobile-first, accessible, semantic HTML; link style.css and script.js from index.html using relative paths; no external scripts, no tracking, no remote fonts; images only as inline SVG or CSS gradients; write the site copy in the same language as the user request; keep total size under 150 KB.';
  const user = `Website request: ${prompt}\nSite name: ${name || '(choose a fitting name)'}\nPrimary brand color: ${color}`;
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: ANTHROPIC_MODEL, max_tokens: 16000, system, messages: [{ role: 'user', content: user }] }),
    signal: AbortSignal.timeout(140000)
  });
  const data = await r.json().catch(() => null);
  if (!r.ok || !data) { console.error('AI error', r.status, data && data.error && data.error.message); return fail(res, 502, 'AI service error. Please try again.'); }
  const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
  let files;
  try { const s = text.indexOf('{'), e = text.lastIndexOf('}'); files = JSON.parse(text.slice(s, e + 1)).files; } catch (e) { return fail(res, 502, 'AI returned an unreadable response. Please try again.'); }
  const bad = validateFiles(files); if (bad) return fail(res, 502, 'AI returned an invalid site. Please try again.');
  res.json({ files });
}));

app.use('/api', (req, res) => fail(res, 404, 'Not found.'));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.too.large') return fail(res, 413, 'Request is too large.');
  if (err && err.type === 'entity.parse.failed') return fail(res, 400, 'Invalid JSON.');
  console.error(err && err.message); fail(res, 500, 'Internal server error.');
});

app.listen(PORT, () => {
  console.log(`WebCraft backend listening on :${PORT}`);
  console.log(`  hosting: ${hostingReady ? 'ON' : 'OFF (set CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID)'} | google: ${googleReady ? 'ON' : 'OFF'} | ai: ${aiReady ? 'ON' : 'OFF'}`);
});
