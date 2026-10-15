import { sigv4Presign, uriEncode } from './sigv4.js';

const QUOTA = 10 * 1000 ** 3; // B2 free tier: 10 GB
const SINGLE_MAX = 90 * 1000 ** 2; // up to here: one request. Cloudflare's free plan caps request bodies at 100 MB
const PART_SIZE = 50 * 1024 * 1024; // bigger files are uploaded in 50 MiB parts
const THUMB_MAX = 512 * 1024;
const SESSION_TTL = 7 * 24 * 3600; // 7 days
const COOKIE = 'av_session';
const PURGE_BATCH = 20; // keep subrequests low on the Workers free plan
const SAFE_IMG = /^image\/(png|jpe?g|gif|webp|avif|bmp)$/i;
const MEDIA = {
  mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', ogv: 'video/ogg',
  mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', wav: 'audio/wav', ogg: 'audio/ogg',
  oga: 'audio/ogg', opus: 'audio/ogg', flac: 'audio/flac',
};
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
    sha: r.sha256 || null,
    thumb: !!r.thumb,
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

function b2Presign(env, method, key, expires = 900, query = {}) {
  need(env, ['B2_KEY_ID', 'B2_APP_KEY', 'B2_BUCKET', 'B2_ENDPOINT']);
  const host = env.B2_ENDPOINT;
  const region = env.B2_REGION || host.split('.')[1];
  const scheme = /^(localhost|127\.0\.0\.1)(:|$)/.test(host) ? 'http' : 'https';
  const path = '/' + env.B2_BUCKET + '/' + key.split('/').map(uriEncode).join('/');
  return sigv4Presign({ method, host, path, region, keyId: env.B2_KEY_ID, secret: env.B2_APP_KEY, expires, query, scheme });
}

async function b2Fetch(env, method, key, { query = {}, body, headers, expires = 300 } = {}) {
  return fetch(await b2Presign(env, method, key, expires, query), { method, body, headers });
}

async function b2Err(up, what) {
  let code = '', msg = '';
  try {
    const t = (await up.text()).slice(0, 2000);
    code = (t.match(/<Code>([^<]*)<\/Code>/) || [])[1] || '';
    msg = (t.match(/<Message>([^<]*)<\/Message>/) || [])[1] || '';
  } catch (e) {}
  const cap = /cap|quota|limit/i.test(code + ' ' + msg) || up.status === 403 && /exceed/i.test(msg);
  const detail = [code, msg].filter(Boolean).join(': ');
  return json({ error: what + ' (' + up.status + (detail ? ' — ' + detail : '') + ')', cap }, 502);
}
async function b2Delete(env, key) {
  const res = await b2Fetch(env, 'DELETE', key, { expires: 60 });
  if (!res.ok && res.status !== 404) throw new HttpError(502, 'B2 delete failed (' + res.status + ')');
}

async function mpCreate(env, key) {
  const r = await b2Fetch(env, 'POST', key, { query: { uploads: '' } });
  const t = await r.text();
  const id = (t.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
  if (!r.ok || !id) throw new HttpError(502, 'Storage could not start the upload (' + r.status + ')');
  return id;
}

async function mpAbort(env, key, uploadId) {
  try {
    await b2Fetch(env, 'DELETE', key, { query: { uploadId }, expires: 60 });
  } catch (e) {
    console.error('abort failed', e);
  }
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
    } else if (MEDIA[ext]) {
      type = MEDIA[ext];
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
  if (disp === 'inline' && SAFE_IMG.test(mime)) out.set('cache-control', 'private, max-age=3600');
  if (disp === 'inline' && MEDIA[ext]) out.set('accept-ranges', 'bytes');
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

async function usage(env) {
  return env.DB.prepare(
    "SELECT COALESCE(SUM(CASE WHEN status = 'ready' THEN size END), 0) AS ready, COALESCE(SUM(CASE WHEN status = 'pending' THEN size END), 0) AS pending FROM items WHERE type = 'file'",
  ).first();
}

// Adds the newer columns/tables on first use, so no manual database step is needed.
let schemaPromise = null;
function ensureSchema(env) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      const info = await env.DB.prepare('PRAGMA table_info(items)').all();
      const cols = new Set(info.results.map((c) => c.name));
      for (const col of ['upload_id', 'sha256', 'thumb']) {
        if (!cols.has(col)) {
          try {
            await env.DB.prepare(`ALTER TABLE items ADD COLUMN ${col} TEXT`).run();
          } catch (e) {
            console.error('migration', col, e);
          }
        }
      }
      await env.DB.prepare(
        'CREATE TABLE IF NOT EXISTS parts (item_id TEXT NOT NULL, n INTEGER NOT NULL, etag TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY (item_id, n))',
      ).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_items_sha ON items(sha256)').run();
    })().catch((e) => {
      schemaPromise = null;
      throw e;
    });
  }
  return schemaPromise;
}

async function descendants(env, id) {
  const out = [];
  let frontier = [id];
  while (frontier.length) {
    const next = [];
    for (let i = 0; i < frontier.length; i += 90) {
      const chunk = frontier.slice(i, i + 90);
      const ph = chunk.map(() => '?').join(',');
      const { results } = await env.DB.prepare(`SELECT id, type, b2_key, thumb FROM items WHERE parent IN (${ph})`).bind(...chunk).all();
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
  await ensureSchema(env);

  let mm;

  if (p === '/api/items' && m === 'GET') {
    // sweep uploads that never finished (single uploads after 6 h, multi-part after 3 days of silence)
    const now = Date.now();
    const stale = await env.DB.prepare(
      "SELECT id, b2_key, upload_id FROM items WHERE status = 'pending' AND ((upload_id IS NULL AND mod < ?) OR (upload_id IS NOT NULL AND mod < ?)) LIMIT 10",
    ).bind(now - 6 * 3600 * 1000, now - 3 * 24 * 3600 * 1000).all();
    if (stale.results.length) {
      ctx.waitUntil(
        (async () => {
          for (const r of stale.results) {
            try {
              if (r.upload_id) await mpAbort(env, r.b2_key, r.upload_id);
              else await b2Delete(env, r.b2_key);
              await env.DB.batch([
                env.DB.prepare('DELETE FROM parts WHERE item_id = ?').bind(r.id),
                env.DB.prepare('DELETE FROM items WHERE id = ?').bind(r.id),
              ]);
            } catch (e) {
              console.error('stale sweep failed', e);
            }
          }
        })(),
      );
    }
    const { results } = await env.DB.prepare("SELECT * FROM items WHERE status = 'ready'").all();
    return json({ items: results.map(itemOut), used: (await usage(env)).ready, quota: QUOTA });
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
    if (size > QUOTA) return json({ error: 'The vault is full (10 GB)' }, 413);
    const parent = b.parent || null;
    if (parent) {
      const pr = await getItem(env, parent);
      if (!pr || pr.type !== 'folder') return json({ error: 'Parent folder not found' }, 400);
    }
    const sha = typeof b.sha === 'string' && /^[a-f0-9]{64}$/.test(b.sha) ? b.sha : null;
    const parts = Math.ceil(size / PART_SIZE);

    if (size > SINGLE_MAX) {
      // an interrupted upload of the same file? pick it up where it stopped
      const ex = await env.DB.prepare(
        "SELECT * FROM items WHERE status = 'pending' AND upload_id IS NOT NULL AND name = ? AND size = ? AND parent IS ? LIMIT 1",
      ).bind(name, size, parent).first();
      if (ex) {
        const { results } = await env.DB.prepare('SELECT n FROM parts WHERE item_id = ? ORDER BY n').bind(ex.id).all();
        await env.DB.prepare('UPDATE items SET mod = ?, sha256 = COALESCE(?, sha256) WHERE id = ?').bind(Date.now(), sha, ex.id).run();
        return json({ id: ex.id, multipart: true, partSize: PART_SIZE, parts, done: results.map((r) => r.n), resumed: true });
      }
    }

    const u = await usage(env);
    if (u.ready + u.pending + size > QUOTA) return json({ error: 'The vault is full (10 GB)' }, 413);
    const mime = typeof b.mime === 'string' && b.mime.length < 128 ? b.mime : 'application/octet-stream';
    const id = crypto.randomUUID();
    const key = 'f/' + id;
    await env.DB.prepare("INSERT INTO items (id, name, type, parent, size, mime, b2_key, sha256, status, mod) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, 'pending', ?)")
      .bind(id, name, parent, size, mime, key, sha, Date.now()).run();

    if (size > SINGLE_MAX) {
      try {
        const uploadId = await mpCreate(env, key);
        await env.DB.prepare('UPDATE items SET upload_id = ? WHERE id = ?').bind(uploadId, id).run();
      } catch (e) {
        await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(id).run();
        throw e;
      }
      return json({ id, multipart: true, partSize: PART_SIZE, parts, done: [] }, 201);
    }
    return json({ id }, 201);
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/content$/)) && m === 'PUT') {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file' || row.status !== 'pending' || row.upload_id) return json({ error: 'Not found' }, 404);
    const len = parseInt(request.headers.get('content-length') || '', 10);
    if (!Number.isFinite(len) || len < 0 || len > SINGLE_MAX) return json({ error: 'Invalid file size' }, 413);
    const up = await fetch(await b2Presign(env, 'PUT', row.b2_key, 600), {
      method: 'PUT',
      body: len > 0 ? request.body : null,
      headers: { 'content-length': String(len), 'content-type': row.mime || 'application/octet-stream' },
    });
    if (!up.ok) return b2Err(up, 'Storage rejected the upload');
    await env.DB.prepare("UPDATE items SET status = 'ready', size = ?, mod = ? WHERE id = ?")
      .bind(len, Date.now(), row.id).run();
    return json(itemOut(await getItem(env, row.id)));
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/parts\/(\d+)$/)) && m === 'PUT') {
    const row = await getItem(env, mm[1]);
    const n = parseInt(mm[2], 10);
    if (!row || row.type !== 'file' || row.status !== 'pending' || !row.upload_id) return json({ error: 'Not found' }, 404);
    const total = Math.ceil(row.size / PART_SIZE);
    if (n < 1 || n > total) return json({ error: 'Bad part number' }, 400);
    const expected = n < total ? PART_SIZE : row.size - (total - 1) * PART_SIZE;
    const len = parseInt(request.headers.get('content-length') || '', 10);
    if (len !== expected) return json({ error: 'Part has the wrong size' }, 400);
    const up = await b2Fetch(env, 'PUT', row.b2_key, {
      query: { partNumber: String(n), uploadId: row.upload_id },
      body: request.body,
      headers: { 'content-length': String(len) },
      expires: 900,
    });
    const etag = up.headers.get('etag');
    if (!up.ok || !etag) return b2Err(up, 'Storage rejected part ' + n);
    await env.DB.batch([
      env.DB.prepare('INSERT OR REPLACE INTO parts (item_id, n, etag, size) VALUES (?, ?, ?, ?)').bind(row.id, n, etag, len),
      env.DB.prepare('UPDATE items SET mod = ? WHERE id = ?').bind(Date.now(), row.id),
    ]);
    return json({ ok: true, n });
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/complete$/)) && m === 'POST') {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file') return json({ error: 'Not found' }, 404);
    if (row.status === 'ready') return json(itemOut(row));
    if (row.upload_id) {
      const total = Math.ceil(row.size / PART_SIZE);
      const { results } = await env.DB.prepare('SELECT n, etag FROM parts WHERE item_id = ? ORDER BY n').bind(row.id).all();
      const have = new Set(results.map((r) => r.n));
      const missing = [];
      for (let i = 1; i <= total; i++) if (!have.has(i)) missing.push(i);
      if (missing.length) return json({ error: 'Some parts are missing', missing }, 409);
      const xml = '<CompleteMultipartUpload>' + results.map((r) => `<Part><PartNumber>${r.n}</PartNumber><ETag>${r.etag}</ETag></Part>`).join('') + '</CompleteMultipartUpload>';
      const res = await b2Fetch(env, 'POST', row.b2_key, {
        query: { uploadId: row.upload_id },
        body: xml,
        headers: { 'content-type': 'application/xml' },
        expires: 300,
      });
      const txt = await res.text();
      if (!res.ok || /<Error>/.test(txt)) return json({ error: 'Storage could not assemble the file (' + res.status + ')' }, 502);
    }
    const head = await b2Fetch(env, 'HEAD', row.b2_key, { expires: 60 });
    if (!head.ok) return json({ error: 'Upload not found in storage' }, 409);
    const size = parseInt(head.headers.get('content-length') || '', 10);
    await env.DB.batch([
      env.DB.prepare("UPDATE items SET status = 'ready', size = ?, mod = ?, upload_id = NULL WHERE id = ?").bind(Number.isFinite(size) ? size : row.size, Date.now(), row.id),
      env.DB.prepare('DELETE FROM parts WHERE item_id = ?').bind(row.id),
    ]);
    return json(itemOut(await getItem(env, row.id)));
  }

  if ((mm = p.match(/^\/api\/files\/([\w-]+)\/thumb$/))) {
    const row = await getItem(env, mm[1]);
    if (!row || row.type !== 'file' || row.status !== 'ready') return json({ error: 'Not found' }, 404);
    if (m === 'PUT') {
      const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
      if (!['image/webp', 'image/jpeg', 'image/png'].includes(ct)) return json({ error: 'Unsupported thumbnail type' }, 415);
      const len = parseInt(request.headers.get('content-length') || '', 10);
      if (!(len > 0 && len <= THUMB_MAX)) return json({ error: 'Thumbnail too large' }, 413);
      const up = await b2Fetch(env, 'PUT', 't/' + row.id, { body: request.body, headers: { 'content-length': String(len), 'content-type': ct } });
      if (!up.ok) return b2Err(up, 'Storage rejected the thumbnail');
      await env.DB.prepare('UPDATE items SET thumb = ? WHERE id = ?').bind(ct, row.id).run();
      return json({ ok: true });
    }
    if (m === 'GET') {
      if (!row.thumb) return json({ error: 'No thumbnail' }, 404);
      const up = await b2Fetch(env, 'GET', 't/' + row.id, { expires: 120 });
      if (!up.ok) return json({ error: 'No thumbnail' }, 404);
      const out = new Headers({
        'content-type': row.thumb,
        'cache-control': 'private, max-age=31536000, immutable',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'none'; sandbox",
      });
      const cl = up.headers.get('content-length');
      if (cl) out.set('content-length', cl);
      return new Response(up.body, { status: 200, headers: out });
    }
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
      for (const f of batch) {
        await b2Delete(env, f.b2_key);
        if (f.thumb) await b2Delete(env, 't/' + f.id);
      }
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
