import { sigv4Presign, uriEncode } from './sigv4.js';

const QUOTA = 10 * 1000 ** 3; // B2 free tier: 10 GB
const MAX_FILE = 95 * 1000 ** 2; // Cloudflare's free plan caps request bodies at 100 MB
const SESSION_TTL = 7 * 24 * 3600; // 7 days
const COOKIE = 'av_session';
const PURGE_BATCH = 30; // keep subrequests low on the Workers free plan
const SAFE_IMG = /^image\/(png|jpe?g|gif|webp|avif|bmp)$/i;
const TEXT_EXT = new Set(['txt', 'md', 'json', 'csv', 'log', 'xml', 'yml', 'yaml', 'ini', 'js', 'css', 'html']);

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/* ---------- small helpers ---------- */

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra },
  });
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function need(env, keys) {
  const missing = keys.filter((k) => !env[k]);
  if (missing.length) throw new HttpError(500, 'Server not configured, missing: ' + missing.join(', '));
}

async function hmacHex(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function getCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function cleanName(v) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s && s.length <= 255 ? s : null;
}

function itemOut(r) {
  return {
    id: r.id,
    name: r.name,
    type: r.type,
    parent: r.parent,
    size: r.size,
    mime: r.mime,
    star: !!r.star,
    trash: !!r.trash,
    shared: !!r.share_token,
    mod: r.mod,
  };
}

/* ---------- sessions ---------- */

async function makeSession(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const payload = `${exp}.${nonce}`;
  return `${payload}.${await hmacHex(env.SESSION_SECRET, payload)}`;
}

async function isAuthed(env, request) {
  need(env, ['SESSION_SECRET']);
  const tok = getCookie(request, COOKIE);
  if (!tok) return false;
  const i = tok.lastIndexOf('.');
  if (i < 0) return false;
  const payload = tok.slice(0, i);
  const sig = tok.slice(i + 1);
  const exp = parseInt(payload.split('.')[0], 10);
  if (!exp || exp < Date.now() / 1000) return false;
  return safeEqual(sig, await hmacHex(env.SESSION_SECRET, payload));
}

function cookieHeader(url, value, maxAge) {
  const secure = url.protocol === 'https:' ? '; Secure' : '';
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

async function login(request, env, url) {
  need(env, ['VAULT_PASSWORD', 'SESSION_SECRET']);
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const since = Date.now() - 15 * 60 * 1000;

  await env.DB.prepare('DELETE FROM login_attempts WHERE ts < ?').bind(since).run();
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND ts > ?').bind(ip, since).first();
  if (row.n >= 8) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

  const body = await request.json().catch(() => null);
  const pw = body && typeof body.password === 'string' ? body.password : '';
  const a = await hmacHex(env.SESSION_SECRET, 'pw:' + pw);
  const b = await hmacHex(env.SESSION_SECRET, 'pw:' + env.VAULT_PASSWORD);
  if (!safeEqual(a, b)) {
    await env.DB.prepare('INSERT INTO login_attempts (ip, ts) VALUES (?, ?)').bind(ip, Date.now()).run();
    return json({ error: 'Wrong password' }, 401);
  }
  await env.DB.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run();
  return json({ ok: true }, 200, { 'set-cookie': cookieHeader(url, await makeSession(env), SESSION_TTL) });
}

/* ---------- Backblaze B2 (S3 API) ---------- */

function b2Presign(env, method, key, expires = 900) {
  need(env, ['B2_KEY_ID', 'B2_APP_KEY', 'B2_BUCKET', 'B2_ENDPOINT']);
  const host = env.B2_ENDPOINT;
  const region = host.split('.')[1];
  const path = '/' + env.B2_BUCKET + '/' + key.split('/').map(uriEncode).join('/');
  return sigv4Presign({ method, host, path, region, keyId: env.B2_KEY_ID, secret: env.B2_APP_KEY, expires });
}

async function b2Delete(env, key) {
  const res = await fetch(await b2Presign(env, 'DELETE', key, 60), { method: 'DELETE' });
  if (!res.ok && res.status !== 404) throw new HttpError(502, 'B2 delete failed (' + res.status + ')');
}

async function serveFile(env, request, row, inline) {
  const headers = new Headers();
  const range = request.headers.get('range');
  if (range) headers.set('range', range);
  const up = await fetch(await b2Presign(env, 'GET', row.b2_key, 120), { headers });
  if (!up.ok && up.status !== 206) {
    return json({ error: up.status === 404 ? 'File missing in storage' : 'Storage error' }, up.status === 404 ? 404 : 502);
  }

  const ext = (row.name.split('.').pop() || '').toLowerCase();
  const mime = row.mime || '';
  let type = 'application/octet-stream';
  let disp = 'attachment';
  if (inline) {
    if (SAFE_IMG.test(mime)) {
      type = mime;
      disp = 'inline';
    } else if (mime.startsWith('text/') || TEXT_EXT.has(ext)) {
      type = 'text/plain; charset=utf-8';
      disp = 'inline';
    }
  }
  const ascii = row.name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  const out = new Headers({
    'content-type': type,
    'content-disposition': `${disp}; filename="${ascii}"; filename*=UTF-8''${uriEncode(row.name)}`,
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; sandbox",
    'cache-control': 'private, no-store',
  });
  for (const h of ['content-length', 'content-range', 'accept-ranges', 'etag', 'last-modified']) {
    const v = up.headers.get(h);
    if (v) out.set(h, v);
  }
  return new Response(up.body, { status: up.status, headers: out });
}

/* ---------- API ---------- */

async function getItem(env, id) {
  return env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
}

async function usedBytes(env) {
  const r = await env.DB.prepare("SELECT COALESCE(SUM(size), 0) AS n FROM items WHERE type = 'file'").first();
  return r.n;
}

async function descendants(env, id) {
  const out = [];
  let frontier = [id];
  while (frontier.length) {
    const next = [];
    for (let i = 0; i < frontier.length; i += 90) {
      const chunk = frontier.slice(i, i + 90);
      const ph = chunk.map(() => '?').join(',');
      const { results } = await env.DB.prepare(`SELECT id, type, b2_key FROM items WHERE parent IN (${ph})`).bind(...chunk).all();
      out.push(...results);
      next.push(...results.filter((r) => r.type === 'folder').map((r) => r.id));
    }
    frontier = next;
  }
  return out;
}

async function api(request, env, ctx, url) {
  const m = request.method;
  const p = url.pathname;

  // Custom header = browsers can't send it cross-site without a CORS preflight, which we never allow.
  if (m !== 'GET' && m !== 'HEAD' && request.headers.get('x-requested-with') !== 'vault') {
    return json({ error: 'Bad request' }, 400);
  }

  if (p === '/api/login' && m === 'POST') return login(request, env, url);
  if (p === '/api/logout' && m === 'POST') {
    return json({ ok: true }, 200, { 'set-cookie': cookieHeader(url, '', 0) });
  }
  if (!(await isAuthed(env, request))) return json({ error: 'Unauthorized' }, 401);
  if (p === '/api/me' && m === 'GET') return json({ ok: true });

  let mm;

  if (p === '/api/items' && m === 'GET') {
    // sweep uploads that never finished
    const stale = await env.DB.prepare("SELECT id, b2_key FROM items WHERE status = 'pending' AND mod < ? LIMIT 20")
      .bind(Date.now() - 24 * 3600 * 1000).all();
    if (stale.results.length) {
      ctx.waitUntil(
        (async () => {
          for (const r of stale.results) {
            try {
              await b2Delete(env, r.b2_key);
              await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(r.id).run();
            } catch (e) {
              console.error('stale sweep failed', e);
            }
          }
        })(),
      );
    }
    const { results } = await env.DB.prepare("SELECT * FROM items WHERE status = 'ready'").all();
    return json({ items: results.map(itemOut), used: await usedBytes(env), quota: QUOTA });
  }

  if (p === '/api/folders' && m === 'POST') {
    const b = await request.json().catch(() => null);
    const name = b && cleanName(b.name);
    if (!name) return json({ error: 'Invalid folder name' }, 400);
    const parent = b.parent || null;
    if (parent) {
      const pr = await getItem(env, parent);
      if (!pr || pr.type !== 'folder') return json({ error: 'Parent folder not found' }, 400);
    }
    const id = crypto.randomUUID();
    const mod = Date.now();
    await env.DB.prepare("INSERT INTO items (id, name, type, parent, size, status, mod) VALUES (?, ?, 'folder', ?, 0, 'ready', ?)")
      .bind(id, name, parent, mod).run();
    return json(itemOut(await getItem(env, id)), 201);
  }

  if (p === '/api/files/init' && m === 'POST') {
    const b = await request.json().catch(() => null);
    const name = b && cleanName(b.name);
    const size = b && Number.isFinite(b.size) ? Math.floor(b.size) : -1;
    if (!name || size < 0) return json({ error: 'Invalid file' }, 400);
    if (size > MAX_FILE) return json({ error: 'Files over 95 MB are not supported yet' }, 413);
    if ((await usedBytes(env)) + size > QUOTA) return json({ error: 'The vault is full (10 GB)' }, 413);
    const parent = b.parent || null;
    if (parent) {
      const pr = await getItem(env, parent);
      if (!pr || pr.type !== 'folder') return json({ error: 'Parent folder not found' }, 400);
    }
    const mime = typeof b.mime === 'string' && b.mime.length < 128 ? b.mime : 'application/octet-stream';
    const id = crypto.randomUUID();
    const key = 'f/' + id;
    await env.DB.prepare("INSERT INTO items (id, name, type, parent, size, mime, b2_key, status, mod) VALUES (?, ?, 'file', ?, ?, ?, ?, 'pending', ?)")
      .bind(id, name, parent, size, mime, key, Date.now()).run();
    return json({ id }, 201);
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/content$/)) && m === 'PUT') {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file' || row.status !== 'pending') return json({ error: 'Not found' }, 404);
    const len = parseInt(request.headers.get('content-length') || '', 10);
    if (!Number.isFinite(len) || len < 0 || len > MAX_FILE) return json({ error: 'Invalid file size' }, 413);
    const up = await fetch(await b2Presign(env, 'PUT', row.b2_key, 600), {
      method: 'PUT',
      body: len > 0 ? request.body : null,
      headers: { 'content-length': String(len), 'content-type': row.mime || 'application/octet-stream' },
    });
    if (!up.ok) return json({ error: 'Storage rejected the upload (' + up.status + ')' }, 502);
    await env.DB.prepare("UPDATE items SET status = 'ready', size = ?, mod = ? WHERE id = ?")
      .bind(len, Date.now(), row.id).run();
    return json(itemOut(await getItem(env, row.id)));
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/complete$/)) && m === 'POST') {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file') return json({ error: 'Not found' }, 404);
    const head = await fetch(await b2Presign(env, 'HEAD', row.b2_key, 60), { method: 'HEAD' });
    if (!head.ok) return json({ error: 'Upload not found in storage' }, 409);
    const size = parseInt(head.headers.get('content-length') || '', 10);
    await env.DB.prepare("UPDATE items SET status = 'ready', size = ?, mod = ? WHERE id = ?")
      .bind(Number.isFinite(size) ? size : row.size, Date.now(), row.id).run();
    return json(itemOut(await getItem(env, row.id)));
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/download$/)) && m === 'GET') {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file' || row.status !== 'ready') return json({ error: 'Not found' }, 404);
    return serveFile(env, request, row, url.searchParams.get('inline') === '1');
  }

  if ((mm = p.match(/^\/api\/items\/([\w-]+)$/))) {
    const row = await getItem(env, mm[1]);
    if (!row) return json({ error: 'Not found' }, 404);

    if (m === 'PATCH') {
      const b = await request.json().catch(() => null);
      if (!b) return json({ error: 'Bad request' }, 400);
      const sets = [];
      const vals = [];
      if ('name' in b) {
        const n = cleanName(b.name);
        if (!n) return json({ error: 'Invalid name' }, 400);
        sets.push('name = ?');
        vals.push(n);
      }
      if ('star' in b) {
        sets.push('star = ?');
        vals.push(b.star ? 1 : 0);
      }
      if ('trash' in b) {
        sets.push('trash = ?', 'mod = ?');
        vals.push(b.trash ? 1 : 0, Date.now());
      }
      if (!sets.length) return json({ error: 'Nothing to change' }, 400);
      await env.DB.prepare(`UPDATE items SET ${sets.join(', ')} WHERE id = ?`).bind(...vals, row.id).run();
      return json(itemOut(await getItem(env, row.id)));
    }

    if (m === 'DELETE') {
      if (!row.trash) return json({ error: 'Move it to deleted files first' }, 400);
      const kids = row.type === 'folder' ? await descendants(env, row.id) : [];
      const files = [...kids.filter((k) => k.type === 'file'), ...(row.type === 'file' ? [row] : [])];
      const batch = files.slice(0, PURGE_BATCH);
      for (const f of batch) await b2Delete(env, f.b2_key);
      if (batch.length) {
        await env.DB.batch(batch.map((f) => env.DB.prepare('DELETE FROM items WHERE id = ?').bind(f.id)));
      }
      if (files.length > batch.length) return json({ done: false, remaining: files.length - batch.length });
      const rest = [...kids.filter((k) => k.type === 'folder'), ...(row.type === 'folder' ? [row] : [])];
      for (let i = 0; i < rest.length; i += 90) {
        await env.DB.batch(rest.slice(i, i + 90).map((f) => env.DB.prepare('DELETE FROM items WHERE id = ?').bind(f.id)));
      }
      return json({ done: true });
    }
  }

  if ((mm = p.match(/^\/api\/items\/([\w-]+)\/share$/))) {
    const row = await getItem(env, mm[1]);
    if (!row) return json({ error: 'Not found' }, 404);
    if (row.type !== 'file') return json({ error: 'Only files can be shared' }, 400);
    if (m === 'POST') {
      let token = row.share_token;
      if (!token) {
        token = (crypto.randomUUID() + crypto.randomUUID()).replace(/-/g, '');
        await env.DB.prepare('UPDATE items SET share_token = ? WHERE id = ?').bind(token, row.id).run();
      }
      return json({ token, url: `${url.origin}/s/${token}` });
    }
    if (m === 'DELETE') {
      await env.DB.prepare('UPDATE items SET share_token = NULL WHERE id = ?').bind(row.id).run();
      return json({ ok: true });
    }
  }

  return json({ error: 'Not found' }, 404);
}

/* ---------- public share links ---------- */

async function shared(request, env, url) {
  const token = url.pathname.slice(3);
  if (!/^[a-f0-9]{64}$/.test(token)) return new Response('Not found', { status: 404 });
  const row = await env.DB.prepare("SELECT * FROM items WHERE share_token = ? AND trash = 0 AND status = 'ready'").bind(token).first();
  if (!row) return new Response('Not found', { status: 404 });
  return serveFile(env, request, row, false);
}

/* ---------- entry ---------- */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/s/')) return await shared(request, env, url);
      if (url.pathname.startsWith('/api/')) return await api(request, env, ctx, url);
      return env.ASSETS.fetch(request);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'Server error' }, 500);
    }
  },
};
