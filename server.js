'use strict';
// ============================================================
//  Dashboard de Demandas - Grupo Via Porto (servidor Node)
//  Destinado a hospedagem em nuvem (Render + Supabase)
//  Rotas: /api/ping | /api/login | /api/logout | /api/data
//         /api/save-data | /api/usuarios | /api/enviar-email
//  Arquivos estaticos: dashboard-demandas.html, logos/...
// ============================================================
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCRIPT_DIR = __dirname;
const DATA_FILE = path.join(SCRIPT_DIR, 'data.json');
const USERS_FILE = path.join(SCRIPT_DIR, 'usuarios.json');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// ---------------- estado ----------------
const state = {
  data: { rev: 0, demands: [], brands: [], resps: [], monthly: [] },
  users: [],
  sessions: new Map(), // token -> { username, at }
  saveQueue: Promise.resolve()
};

// ---------------- helpers ----------------
function toHex(bytes) { return Buffer.from(bytes).toString('hex'); }
function hashPass(pass, salt) {
  return crypto.createHash('sha256').update(salt + ':' + pass).digest('hex');
}
function newSalt() { return toHex(crypto.randomBytes(16)); }
function newUser(u, p, role) {
  const salt = newSalt();
  return { username: u, role, salt, hash: hashPass(p, salt) };
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
function writeJson(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj), 'utf8');
  fs.renameSync(tmp, file);
}
function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 50e6) { req.destroy(); reject(new Error('corpo_grande')); } });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
function getToken(req) {
  const ck = req.headers.cookie || '';
  const m = ck.match(/gd_session=([^;]*)/);
  return m ? m[1] : null;
}
function getAuth(req) {
  const t = getToken(req);
  if (!t) return { ok: false };
  const s = state.sessions.get(t);
  if (!s) return { ok: false };
  if (Date.now() - s.at > SESSION_TTL_MS) { state.sessions.delete(t); return { ok: false }; }
  const rec = state.users.find(u => u.username === s.username);
  if (!rec) return { ok: false };
  s.at = Date.now();
  return { ok: true, role: rec.role, user: rec.username };
}
function hasRole(auth, req) {
  if (!auth.ok) return false;
  if (req === 'admin') return auth.role === 'admin';
  return true;
}
function publicUser(u) { return { username: u.username, role: u.role }; }
function dataPayload(auth) {
  return { ok: true, rev: state.data.rev, isAdmin: auth.role === 'admin', user: auth.user, data: state.data };
}

// ---------------- persistencia Supabase ----------------
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE || '';
const SUPABASE_HEADERS = { apikey: SUPABASE_SERVICE_ROLE, Authorization: 'Bearer ' + SUPABASE_SERVICE_ROLE, 'Content-Type': 'application/json', Prefer: 'return=minimal' };

async function sbFetch(path, opts) {
  const o = opts || {};
  const headers = Object.assign({}, SUPABASE_HEADERS, o.headers || {});
  const r = await fetch(SUPABASE_URL + path, { method: o.method || 'GET', headers, body: o.body });
  if (!r.ok) { const t = await r.text().catch(() => ''); throw new Error('supabase ' + r.status + ' ' + t.slice(0, 120)); }
  return r;
}
async function loadFromSupabase() {
  if (!SUPABASE_URL) return false;
  const r = await sbFetch('/rest/v1/app_data?select=*&id=eq.1');
  const rows = await r.json();
  if (!rows || !rows.length) return false;
  const row = rows[0];
  state.data = {
    rev: Number(row.rev) || 0,
    demands: row.demands || [],
    brands: row.brands || [],
    resps: row.resps || [],
    monthly: row.monthly || []
  };
  const ru = await sbFetch('/rest/v1/usuarios?select=*');
  state.users = await ru.json();
  return true;
}
function saveDataFile() {
  state.saveQueue = state.saveQueue.then(async () => {
    try {
      if (SUPABASE_URL) {
        const payload = {
          rev: state.data.rev,
          demands: state.data.demands,
          brands: state.data.brands,
          resps: state.data.resps,
          monthly: state.data.monthly,
          updated_at: new Date().toISOString()
        };
        await sbFetch('/rest/v1/app_data?id=eq.1', { method: 'PATCH', headers: SUPABASE_HEADERS, body: JSON.stringify(payload) });
      } else {
        writeJson(DATA_FILE, state.data);
      }
    } catch (e) { console.error('Erro salvando dados:', e.message); }
  });
}
function saveUsersFile() {
  state.saveQueue = state.saveQueue.then(async () => {
    try {
      if (SUPABASE_URL) {
        for (const u of state.users) {
          const body = { username: u.username, role: u.role, salt: u.salt, hash: u.hash };
          await sbFetch('/rest/v1/usuarios?on_conflict=username', { method: 'POST', headers: SUPABASE_HEADERS, body: JSON.stringify(body) });
        }
      } else {
        writeJson(USERS_FILE, state.users);
      }
    } catch (e) { console.error('Erro salvando usuarios:', e.message); }
  });
}
function seedUsers() {
  if (SUPABASE_URL) return; // carregado em loadFromSupabase
  const data = readJson(USERS_FILE, null);
  if (data && Array.isArray(data)) { state.users = data; return; }
  state.users = [
    newUser('admin', 'admin123', 'admin'),
    newUser('eduardo.brenes', 'brenes01', 'colaborador'),
    newUser('eduardo.silva', 'edusilva02', 'colaborador')
  ];
  saveUsersFile();
}
function seedData() {
  if (SUPABASE_URL) return; // carregado em loadFromSupabase
  const d = readJson(DATA_FILE, null);
  if (d && typeof d === 'object') {
    state.data = {
      rev: Number(d.rev) || 0,
      demands: Array.isArray(d.demands) ? d.demands : [],
      brands: Array.isArray(d.brands) ? d.brands : [],
      resps: Array.isArray(d.resps) ? d.resps : [],
      monthly: Array.isArray(d.monthly) ? d.monthly : []
    };
    return;
  }
  // Migracao a partir do HTML embutido (se existir)
  try {
    const html = fs.readFileSync(path.join(SCRIPT_DIR, 'dashboard-demandas.html'), 'utf8');
    const tag = '<script id="app-data"';
    const s = html.indexOf(tag);
    if (s >= 0) {
      const a = html.indexOf('>', s) + 1;
      const b = html.indexOf('</script>', a);
      const e = JSON.parse(html.slice(a, b));
      state.data = {
        rev: 0,
        demands: e.demands || [],
        brands: e.brands || [],
        resps: e.resps || [],
        monthly: e.monthly || []
      };
    }
  } catch (e) { console.error('Migracao do HTML falhou:', e.message); }
  saveDataFile();
}

// ---------------- email (Resend; Fase 4) ----------------
async function enviarEmail(destinatario, assunto, corpoHtml) {
  const key = process.env.RESEND_API_KEY;
  if (!key) return { ok: false, msg: 'RESEND_API_KEY nao configurada' };
  const from = process.env.EMAIL_FROM || 'Dashboard Demandas <onboarding@resend.dev>';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [destinatario], subject: assunto, html: corpoHtml })
  });
  const body = await res.json().catch(() => ({}));
  if (res.ok) return { ok: true, id: body.id };
  return { ok: false, msg: (body.message || 'resend_erro') };
}

// ---------------- rotas ----------------
// ---------------- rate limit de login ----------------
const loginAttempts = new Map(); // ip -> { count, resetAt }
function checkLoginLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + 10 * 60 * 1000 });
    return { ok: true };
  }
  rec.count++;
  if (rec.count > 10) return { ok: false, retryIn: Math.ceil((rec.resetAt - now) / 1000) };
  return { ok: true };
}
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

async function handleRequest(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const method = req.method;

  try {
    // ping
    if (method === 'GET' && p === '/api/ping') {
      return sendJson(res, 200, { ok: true, msg: 'Servidor ativo' });
    }

    // login
    if (method === 'POST' && p === '/api/login') {
      const ip = getClientIp(req);
      const lim = checkLoginLimit(ip);
      if (!lim.ok) return sendJson(res, 429, { ok: false, msg: 'Muitas tentativas. Tente novamente em ' + lim.retryIn + 's' });
      const body = await readBody(req);
      const o = (() => { try { return JSON.parse(body); } catch (e) { return null; } })();
      if (!o || !o.username || !o.password) return sendJson(res, 400, { ok: false, msg: 'informacoes invalidas' });
      const rec = state.users.find(u => u.username === o.username);
      if (!rec || hashPass(o.password, rec.salt).toUpperCase() !== String(rec.hash).toUpperCase()) {
        return sendJson(res, 401, { ok: false, msg: 'Usuario ou senha invalidos' });
      }
      const token = crypto.randomBytes(24).toString('hex');
      state.sessions.set(token, { username: rec.username, at: Date.now() });
      res.setHeader('Set-Cookie', 'gd_session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000));
      return sendJson(res, 200, { ok: true, role: rec.role });
    }

    // logout
    if (method === 'POST' && p === '/api/logout') {
      const t = getToken(req);
      if (t) state.sessions.delete(t);
      res.setHeader('Set-Cookie', 'gd_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      return sendJson(res, 200, { ok: true });
    }

    // dados
    if (method === 'GET' && p === '/api/data') {
      const auth = getAuth(req);
      if (!auth.ok) return sendJson(res, 401, { ok: false, msg: 'login' });
      return sendJson(res, 200, dataPayload(auth));
    }

    // salvar dados (conflito -> 409)
    if (method === 'POST' && p === '/api/save-data') {
      const auth = getAuth(req);
      if (!auth.ok) return sendJson(res, 401, { ok: false, msg: 'login' });
      const body = await readBody(req);
      const o = (() => { try { return JSON.parse(body); } catch (e) { return null; } })();
      if (!o) return sendJson(res, 400, { ok: false, msg: 'corpo invalido' });
      if (Number(o.rev) !== Number(state.data.rev)) {
        return sendJson(res, 409, { ok: false, conflict: true, rev: state.data.rev, data: state.data });
      }
      state.data = {
        rev: Number(state.data.rev) + 1,
        demands: Array.isArray(o.data && o.data.demands) ? o.data.demands : state.data.demands,
        brands: Array.isArray(o.data && o.data.brands) ? o.data.brands : state.data.brands,
        resps: Array.isArray(o.data && o.data.resps) ? o.data.resps : state.data.resps,
        monthly: Array.isArray(o.data && o.data.monthly) ? o.data.monthly : state.data.monthly
      };
      saveDataFile();
      return sendJson(res, 200, { ok: true, rev: state.data.rev });
    }

    // usuarios (admin)
    if (p === '/api/usuarios') {
      const auth = getAuth(req);
      if (!hasRole(auth, 'admin')) return sendJson(res, 403, { ok: false, msg: 'sem permissao' });
      if (method === 'GET') {
        const list = state.users.map(publicUser);
        return sendJson(res, 200, { ok: true, usuarios: list });
      }
      if (method === 'POST') {
        const body = await readBody(req);
        const o = (() => { try { return JSON.parse(body); } catch (e) { return null; } })();
        if (!o || !o.username) return sendJson(res, 400, { ok: false, msg: 'username obrigatorio' });
        const u = o.username.trim();
        const rec = state.users.find(x => x.username === u);
        if (rec) {
          if (o.password) { rec.salt = newSalt(); rec.hash = hashPass(o.password, rec.salt); }
          if (o.role) rec.role = o.role;
        } else {
          if (!o.password) return sendJson(res, 400, { ok: false, msg: 'senha obrigatoria' });
          state.users.push(newUser(u, o.password, o.role || 'colaborador'));
        }
        saveUsersFile();
        return sendJson(res, 200, { ok: true });
      }
      if (method === 'DELETE') {
        const u = url.searchParams.get('username');
        if (!u) return sendJson(res, 400, { ok: false, msg: 'username obrigatorio' });
        if (u === 'admin') return sendJson(res, 400, { ok: false, msg: 'admin nao pode ser removido' });
        state.users = state.users.filter(x => x.username !== u);
        saveUsersFile();
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 405, { ok: false, msg: 'metodo nao permitido' });
    }

    // email (qualquer login; Resend)
    if (method === 'POST' && p === '/api/enviar-email') {
      const auth = getAuth(req);
      if (!auth.ok) return sendJson(res, 401, { ok: false, msg: 'login' });
      const body = await readBody(req);
      const o = (() => { try { return JSON.parse(body); } catch (e) { return null; } })();
      if (!o || !o.destinatario) return sendJson(res, 400, { ok: false, msg: 'destinatario obrigatorio' });
      const r = await enviarEmail(o.destinatario, o.assunto || '', o.corpo || '');
      if (!r.ok) return sendJson(res, 200, { ok: false, msg: r.msg || 'resend_erro' });
      return sendJson(res, 200, r);
    }

    // arquivos estaticos (somente whitelist)
    let filePath = path.join(SCRIPT_DIR, p === '/' ? 'dashboard-demandas.html' : p.slice(1));
    if (p.startsWith('/logos/') && !p.includes('..')) {
      filePath = path.join(SCRIPT_DIR, p.slice(1));
    } else if (p !== '/' && !p.startsWith('/dashboard-demandas.html')) {
      return sendJson(res, 404, { ok: false, msg: 'nao encontrado' });
    }
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const type = mimeTypes[ext] || 'application/octet-stream';
      const bytes = fs.readFileSync(filePath);
      res.statusCode = 200;
      res.setHeader('Content-Type', type);
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
      res.end(bytes);
    } else {
      return sendJson(res, 404, { ok: false, msg: 'nao encontrado' });
    }
  } catch (e) {
    console.error('Erro na requisicao:', e.message);
    try { sendJson(res, 500, { ok: false, msg: e.message }); } catch (err) {}
  }
}

// ---------------- inicio ----------------
(async () => {
  try {
    if (SUPABASE_URL) {
      const loaded = await loadFromSupabase();
      if (loaded) console.log('Dados carregados do Supabase (rev ' + state.data.rev + ', ' + state.users.length + ' usuarios)');
      else console.warn('AVISO: Supabase configurado mas sem dados — usando arquivo local');
    }
  } catch (e) {
    console.error('Erro carregando do Supabase:', e.message);
  }
  seedUsers();
  seedData();

  http.createServer(handleRequest).listen(PORT, HOST, () => {
    console.log('==============================================');
    console.log('  Dashboard de Demandas - Grupo Via Porto');
    console.log('  URL: http://' + HOST + ':' + PORT);
    console.log('  Porta: ' + PORT);
    console.log('  Banco: ' + (SUPABASE_URL ? 'Supabase (nuvem)' : 'arquivo local'));
    console.log('  Todos acessam via login (admin/colaborador)');
    console.log('==============================================');
  });
})();
