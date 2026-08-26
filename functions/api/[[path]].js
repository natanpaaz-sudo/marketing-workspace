'use strict';
// ============================================================
//  API do Dashboard de Demandas - Cloudflare Pages Functions
//  Rotas: /api/ping | /api/login | /api/logout | /api/data
//         /api/save-data | /api/usuarios
//  Sessao: cookie assinado (HMAC-SHA256) - stateless
//  Dados: Supabase (service role via env vars)
// ============================================================

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias

// ---------- helpers cripto (Web Crypto - Worker runtime) ----------
function toHex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(buf);
}
async function hashPass(pass, salt) {
  return await sha256Hex(salt + ':' + pass);
}
async function newSalt() {
  const a = crypto.getRandomValues(new Uint8Array(16));
  return toHex(a);
}
async function newUser(u, p, role) {
  const salt = await newSalt();
  return { username: u, role, salt, hash: await hashPass(p, salt) };
}
function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  const b = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = b.length % 4 ? 4 - (b.length % 4) : 0;
  return atob(b + '='.repeat(pad));
}
function fromB64urlBytes(s) {
  const bin = fromB64url(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
async function signSession(username, secret) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ u: username, exp: Date.now() + SESSION_TTL_MS })));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return payload + '.' + b64url(sig);
}
async function verifySession(token, secret) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 2) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, fromB64urlBytes(parts[1]), new TextEncoder().encode(parts[0]));
    if (!ok) return null;
    const data = JSON.parse(fromB64url(parts[0]));
    if (Date.now() > data.exp) return null;
    return data.u;
  } catch (e) { return null; }
}

// ---------- Supabase ----------
async function sbFetch(env, path, opts) {
  const o = opts || {};
  const headers = {
    apikey: env.SUPABASE_SERVICE_ROLE,
    Authorization: 'Bearer ' + env.SUPABASE_SERVICE_ROLE,
    'Content-Type': 'application/json'
  };
  const r = await fetch(env.SUPABASE_URL + path, { method: o.method || 'GET', headers, body: o.body, signal: AbortSignal.timeout(20000) });
  if (!r.ok) { const t = await r.text().catch(() => ''); throw new Error('supabase ' + r.status + ' ' + t.slice(0, 120)); }
  return r;
}
async function loadData(env) {
  const r = await sbFetch(env, '/rest/v1/app_data?select=*&id=eq.1');
  const rows = await r.json();
  return (rows && rows.length) ? rows[0] : null;
}
async function loadUsers(env) {
  const r = await sbFetch(env, '/rest/v1/usuarios?select=*');
  return await r.json();
}

// ---------- helpers ----------
function jsonRes(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
function publicUser(u) { return { username: u.username, role: u.role }; }
function userNameOf(data, username) {
  const r = (data.resps || []).find(r => String(r.name || '').toLowerCase().replace(/\s+/g, '') === String(username || '').toLowerCase().replace(/\s+/g, ''));
  if (r) return r.name;
  return String(username || '').replace(/[._-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
function getToken(request) {
  const ck = request.headers.get('cookie') || '';
  const m = ck.match(/gd_session=([^;]*)/);
  return m ? m[1] : null;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  let p = url.pathname;
  try { p = decodeURIComponent(p); } catch (e) {}
  const method = request.method;

  try {
    // ping
    if (method === 'GET' && p === '/api/ping') {
      return jsonRes(200, { ok: true, msg: 'Servidor ativo' });
    }

    // login
    if (method === 'POST' && p === '/api/login') {
      const body = await request.json().catch(() => null);
      if (!body || !body.username || !body.password) return jsonRes(400, { ok: false, msg: 'informacoes invalidas' });
      const users = await loadUsers(env);
      const rec = users.find(u => u.username === body.username);
      if (!rec || (await hashPass(body.password, rec.salt)).toUpperCase() !== String(rec.hash).toUpperCase()) {
        return jsonRes(401, { ok: false, msg: 'Usuario ou senha invalidos' });
      }
      const token = await signSession(rec.username, env.SESSION_SECRET);
      return new Response(JSON.stringify({ ok: true, role: rec.role }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'Set-Cookie': 'gd_session=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000)
        }
      });
    }

    // logout
    if (method === 'POST' && p === '/api/logout') {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'Set-Cookie': 'gd_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
        }
      });
    }

    // auth
    const token = getToken(request);
    const username = token ? await verifySession(token, env.SESSION_SECRET) : null;

    // dados
    if (method === 'GET' && p === '/api/data') {
      if (!username) return jsonRes(401, { ok: false, msg: 'login' });
      const users = await loadUsers(env);
      const rec = users.find(u => u.username === username);
      if (!rec) return jsonRes(401, { ok: false, msg: 'login' });
      const row = await loadData(env);
      if (!row) return jsonRes(500, { ok: false, msg: 'sem dados' });
      return jsonRes(200, {
        ok: true, rev: Number(row.rev) || 0, isAdmin: rec.role === 'admin', user: rec.username,
        data: { demands: row.demands || [], brands: row.brands || [], resps: row.resps || [], monthly: row.monthly || [] }
      });
    }

    // salvar dados (conflito -> 409)
    if (method === 'POST' && p === '/api/save-data') {
      if (!username) return jsonRes(401, { ok: false, msg: 'login' });
      const users = await loadUsers(env);
      const rec = users.find(u => u.username === username);
      if (!rec) return jsonRes(401, { ok: false, msg: 'login' });
      const body = await request.json().catch(() => null);
      if (!body) return jsonRes(400, { ok: false, msg: 'corpo invalido' });
      const row = await loadData(env);
      if (!row) return jsonRes(500, { ok: false, msg: 'sem dados' });
      const currentRev = Number(row.rev) || 0;
      if (Number(body.rev) !== currentRev) {
        return jsonRes(409, {
          ok: false, conflict: true, rev: currentRev,
          data: { demands: row.demands || [], brands: row.brands || [], resps: row.resps || [], monthly: row.monthly || [] }
        });
      }
      // Fase 3: colaborador so pode criar demanda para si mesmo
      if (rec.role !== 'admin' && body.data && Array.isArray(body.data.demands)) {
        const userName = userNameOf(row, rec.username);
        const novas = body.data.demands.filter(nd => !(row.demands || []).some(od => od.id === nd.id));
        if (novas.length && novas.some(nd => (nd.resp && nd.resp.name || '') !== userName)) {
          return jsonRes(403, { ok: false, msg: 'Colaborador so pode criar demanda para si mesmo' });
        }
      }
      const newData = {
        rev: currentRev + 1,
        demands: Array.isArray(body.data && body.data.demands) ? body.data.demands : (row.demands || []),
        brands: Array.isArray(body.data && body.data.brands) ? body.data.brands : (row.brands || []),
        resps: Array.isArray(body.data && body.data.resps) ? body.data.resps : (row.resps || []),
        monthly: Array.isArray(body.data && body.data.monthly) ? body.data.monthly : (row.monthly || [])
      };
      await sbFetch(env, '/rest/v1/app_data?id=eq.1', { method: 'PATCH', body: JSON.stringify({ ...newData, updated_at: new Date().toISOString() }) });
      return jsonRes(200, { ok: true, rev: newData.rev });
    }

    // usuarios (admin)
    if (p === '/api/usuarios') {
      if (!username) return jsonRes(401, { ok: false, msg: 'login' });
      const users = await loadUsers(env);
      const rec = users.find(u => u.username === username);
      if (!rec || rec.role !== 'admin') return jsonRes(403, { ok: false, msg: 'sem permissao' });
      if (method === 'GET') {
        return jsonRes(200, { ok: true, usuarios: users.map(publicUser) });
      }
      if (method === 'POST') {
        const body = await request.json().catch(() => null);
        if (!body || !body.username) return jsonRes(400, { ok: false, msg: 'username obrigatorio' });
        const u = String(body.username).trim();
        const target = users.find(x => x.username === u);
        if (target) {
          if (body.password) { target.salt = await newSalt(); target.hash = await hashPass(body.password, target.salt); }
          if (body.role) target.role = body.role;
          await sbFetch(env, '/rest/v1/usuarios?username=eq.' + encodeURIComponent(u), { method: 'PATCH', body: JSON.stringify({ salt: target.salt, hash: target.hash, role: target.role }) });
        } else {
          if (!body.password) return jsonRes(400, { ok: false, msg: 'senha obrigatoria' });
          const nu = await newUser(u, body.password, body.role || 'colaborador');
          await sbFetch(env, '/rest/v1/usuarios', { method: 'POST', body: JSON.stringify(nu) });
        }
        return jsonRes(200, { ok: true });
      }
      if (method === 'DELETE') {
        const u = url.searchParams.get('username');
        if (!u) return jsonRes(400, { ok: false, msg: 'username obrigatorio' });
        if (u === 'admin') return jsonRes(400, { ok: false, msg: 'admin nao pode ser removido' });
        await sbFetch(env, '/rest/v1/usuarios?username=eq.' + encodeURIComponent(u), { method: 'DELETE' });
        return jsonRes(200, { ok: true });
      }
      return jsonRes(405, { ok: false, msg: 'metodo nao permitido' });
    }

    return jsonRes(404, { ok: false, msg: 'nao encontrado' });
  } catch (e) {
    return jsonRes(500, { ok: false, msg: e.message });
  }
}