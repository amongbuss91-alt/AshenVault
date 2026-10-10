// Ashen Vault: Cloudflare Pages worker (advanced mode). No dependencies.
// Talks to Backblaze B2 through its S3-compatible API, signing requests with Web Crypto.
// Settings come from Cloudflare variables: B2_ENDPOINT, B2_BUCKET, B2_KEY_ID, B2_APP_KEY, VAULT_PASSWORD.

const META_KEY = '.vault-meta.json'; // stars / trash / shared flags
const enc = new TextEncoder();

// ---------- small helpers ----------
const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
const bad = (m, status = 400) => Object.assign(new Error(m), { status });
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha256hex = async (d) => hex(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? enc.encode(d) : d));
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
const uriEnc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const pathEnc = (k) => k.split('/').map(uriEnc).join('/');
const amzDate = () => new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
const chunk = (a, n) => { const o = []; for (let i = 0; i < a.length; i += n) o.push(a.slice(i, i + n)); return o; };

function cleanKey(k) {
  if (typeof k !== 'string') throw bad('Bad path');
  k = k.replace(/^\/+|\/+$/g, '');
  if (!k || k.length > 900 || /[\u0000-\u001f]/.test(k) || k.split('/').some((p) => p === '' || p === '.' || p === '..')) {
    throw bad('Bad path');
  }
  if (k === META_KEY) throw bad('Reserved name');
  return k;
}

function cfg(env) {
  let ep = env.B2_ENDPOINT;
  if (!/^https?:\/\//.test(ep)) ep = 'https://' + ep;
  const u = new URL(ep);
  const region = (u.host.match(/^s3\.([^.]+)\.backblazeb2\.com$/) || [])[1] || env.B2_REGION || 'us-east-005';
  return { host: u.host, origin: u.origin, region, bucket: env.B2_BUCKET, id: env.B2_KEY_ID, secret: env.B2_APP_KEY };
}

// ---------- AWS Signature V4 ----------
// presign: seconds -> returns a signed URL string. Otherwise sends the request and returns the fetch Response.
// `plain` headers (content-type, content-length) are sent but not signed.
async function s3req(c, { method = 'GET', key = '', query = {}, headers = {}, body, payloadHash, plain = {}, presign = 0 }) {
  const now = amzDate();
  const day = now.slice(0, 8);
  const scope = `${day}/${c.region}/s3/aws4_request`;
  const canonUri = '/' + c.bucket + (key ? '/' + pathEnc(key) : '');
  const q = { ...query };
  const h = { host: c.host };
  let hash;
  if (presign) {
    q['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
    q['X-Amz-Credential'] = `${c.id}/${scope}`;
    q['X-Amz-Date'] = now;
    q['X-Amz-Expires'] = String(presign);
    q['X-Amz-SignedHeaders'] = 'host';
    hash = 'UNSIGNED-PAYLOAD';
  } else {
    for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v).trim();
    hash = payloadHash || (await sha256hex(body ?? ''));
    h['x-amz-content-sha256'] = hash;
    h['x-amz-date'] = now;
  }
  const names = Object.keys(h).sort();
  const canonQuery = Object.keys(q).sort().map((k) => uriEnc(k) + '=' + uriEnc(q[k])).join('&');
  const canonHeaders = names.map((n) => `${n}:${h[n]}\n`).join('');
  const signed = names.join(';');
  const canon = [method, canonUri, canonQuery, canonHeaders, signed, hash].join('\n');
  const sts = ['AWS4-HMAC-SHA256', now, scope, await sha256hex(canon)].join('\n');
  let k = await hmac(enc.encode('AWS4' + c.secret), day);
  k = await hmac(k, c.region);
  k = await hmac(k, 's3');
  k = await hmac(k, 'aws4_request');
  const sig = hex(await hmac(k, sts));

  if (presign) return `${c.origin}${canonUri}?${canonQuery}&X-Amz-Signature=${sig}`;

  const url = `${c.origin}${canonUri}${canonQuery ? '?' + canonQuery : ''}`;
  const out = { ...plain };
  for (const n of names) if (n !== 'host') out[n] = h[n];
  out.authorization = `AWS4-HMAC-SHA256 Credential=${c.id}/${scope}, SignedHeaders=${signed}, Signature=${sig}`;
  return fetch(url, { method, headers: out, body });
}

async function ensure(r) {
  if (r.ok) return r;
  const t = await r.text();
  const m = (t.match(/<Message>([\s\S]*?)<\/Message>/) || [])[1] || r.statusText || 'Storage error';
  throw bad(m, r.status === 404 ? 404 : 502);
}

const unesc = (s) =>
  s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, x) => String.fromCodePoint(parseInt(x, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&amp;/g, '&');

async function listAll(c, prefix = '') {
  const out = [];
  let token;
  do {
    const query = { 'list-type': '2' };
    if (prefix) query.prefix = prefix;
    if (token) query['continuation-token'] = token;
    const xml = await (await ensure(await s3req(c, { query }))).text();
    for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
      const b = m[1];
      const key = unesc((b.match(/<Key>([\s\S]*?)<\/Key>/) || [])[1] || '');
      const size = Number((b.match(/<Size>(\d+)<\/Size>/) || [])[1] || 0);
      const lm = (b.match(/<LastModified>([\s\S]*?)<\/LastModified>/) || [])[1];
      out.push({ key, size, mod: lm ? new Date(lm).getTime() : Date.now() });
    }
    token = /<IsTruncated>true<\/IsTruncated>/.test(xml)
      ? unesc((xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/) || [])[1] || '')
      : undefined;
  } while (token);
  return out;
}

async function readMeta(c) {
  const r = await s3req(c, { key: META_KEY });
  if (r.status === 404) { await r.arrayBuffer(); return {}; }
  await ensure(r);
  return await r.json();
}
const writeMeta = async (c, m) =>
  ensure(await s3req(c, { method: 'PUT', key: META_KEY, body: JSON.stringify(m), plain: { 'content-type': 'application/json' } }));

async function deleteKeys(c, keys) {
  for (const group of chunk(keys, 6)) {
    await Promise.all(group.map(async (key) => {
      const r = await s3req(c, { method: 'DELETE', key });
      if (r.status !== 404) await ensure(r);
      else await r.arrayBuffer();
    }));
  }
}

// ---------- password ----------
async function authOk(request, pw) {
  const h = request.headers.get('authorization') || '';
  if (!h.startsWith('Basic ')) return false;
  let dec;
  try { dec = atob(h.slice(6)); } catch { return false; }
  const given = dec.slice(dec.indexOf(':') + 1);
  const [a, b] = await Promise.all([sha256hex(given), sha256hex(pw)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- routes ----------
async function route(request, url, c) {
  const p = url.pathname;
  const m = request.method;
  const body = async () => { try { return await request.json(); } catch { throw bad('Bad JSON'); } };

  if (m !== 'GET' && m !== 'HEAD') {
    const o = request.headers.get('origin');
    if (o && new URL(o).host !== url.host) return json({ error: 'Bad origin' }, 403);
  }

  if (p === '/api/files' && m === 'GET') {
    const [objs, meta] = await Promise.all([listAll(c), readMeta(c)]);
    return json({ files: objs.filter((o) => o.key !== META_KEY), meta });
  }

  // Upload: the browser PUTs the raw file here, the worker streams it on to B2 (free plan limit: 100 MB per file)
  if (p === '/api/upload' && m === 'PUT') {
    const key = cleanKey(url.searchParams.get('key'));
    if (key.split('/').pop() === '.keep') throw bad('Reserved name');
    const len = request.headers.get('content-length');
    if (!len) throw bad('Length required', 411);
    await ensure(await s3req(c, {
      method: 'PUT', key, body: request.body, payloadHash: 'UNSIGNED-PAYLOAD',
      plain: { 'content-type': request.headers.get('content-type') || 'application/octet-stream', 'content-length': len },
    }));
    return json({ ok: true });
  }

  // View (redirect to a short-lived B2 link), download or raw text (streamed through the worker)
  if (p === '/api/file' && m === 'GET') {
    const key = cleanKey(url.searchParams.get('key'));
    const dl = url.searchParams.get('dl');
    const raw = url.searchParams.get('raw');
    if (!dl && !raw) {
      const link = await s3req(c, { key, presign: 3600 });
      return new Response(null, { status: 302, headers: { location: link, 'cache-control': 'private, max-age=600' } });
    }
    const r = await ensure(await s3req(c, { key }));
    const headers = new Headers({ 'x-content-type-options': 'nosniff', 'cache-control': 'private, no-store' });
    if (raw) {
      headers.set('content-type', 'text/plain; charset=utf-8');
    } else {
      headers.set('content-type', r.headers.get('content-type') || 'application/octet-stream');
      headers.set('content-disposition', `attachment; filename*=UTF-8''${uriEnc(key.split('/').pop())}`);
    }
    const len = r.headers.get('content-length');
    if (len) headers.set('content-length', len);
    return new Response(r.body, { headers });
  }

  // Direct link that works for up to 7 days
  if (p === '/api/share' && m === 'GET') {
    const key = cleanKey(url.searchParams.get('key'));
    const days = Math.min(7, Math.max(1, parseInt(url.searchParams.get('days'), 10) || 7));
    return json({ url: await s3req(c, { key, presign: days * 86400 }), days });
  }

  // Folders are key prefixes, so an empty one gets a ".keep" placeholder
  if (p === '/api/mkdir' && m === 'POST') {
    const dir = cleanKey((await body()).path);
    await ensure(await s3req(c, { method: 'PUT', key: dir + '/.keep', body: '' }));
    return json({ ok: true });
  }

  // Move/rename up to 15 files per call (the page loops for folders; free plan allows 50 subrequests per call)
  if (p === '/api/rename' && m === 'POST') {
    const pairs = (await body()).pairs;
    if (!Array.isArray(pairs) || !pairs.length || pairs.length > 15) throw bad('Bad request');
    const clean = pairs.map(([a, b]) => [cleanKey(a), cleanKey(b)]);
    for (const [a, b] of clean) if (a === b || b.startsWith(a + '/')) throw bad('Cannot move something into itself');
    for (const group of chunk(clean, 5)) {
      await Promise.all(group.map(([a, b]) =>
        s3req(c, { method: 'PUT', key: b, headers: { 'x-amz-copy-source': `${c.bucket}/${pathEnc(a)}` } }).then(ensure)));
    }
    await deleteKeys(c, clean.map((x) => x[0]));
    return json({ ok: true });
  }

  // Permanent delete, up to 40 keys per call
  if (p === '/api/delete' && m === 'POST') {
    const keys = (await body()).keys;
    if (!Array.isArray(keys) || !keys.length || keys.length > 40) throw bad('Bad request');
    await deleteKeys(c, keys.map(cleanKey));
    return json({ ok: true });
  }

  // Star / trash / shared flags
  if (p === '/api/meta' && m === 'POST') {
    const b = await body();
    const key = cleanKey(b.key);
    const patch = b.patch || {};
    const meta = await readMeta(c);
    const cur = meta[key] || {};
    for (const f of ['star', 'trash', 'shared']) if (typeof patch[f] === 'boolean') cur[f] = patch[f];
    if (cur.star || cur.trash || cur.shared) meta[key] = cur; else delete meta[key];
    await writeMeta(c, meta);
    return json({ ok: true });
  }
  if (p === '/api/meta-move' && m === 'POST') {
    const b = await body();
    const from = cleanKey(b.from), to = cleanKey(b.to);
    const meta = await readMeta(c);
    let changed = false;
    for (const k of Object.keys(meta)) {
      if (k === from || k.startsWith(from + '/')) { meta[to + k.slice(from.length)] = meta[k]; delete meta[k]; changed = true; }
    }
    if (changed) await writeMeta(c, meta);
    return json({ ok: true });
  }
  if (p === '/api/meta-drop' && m === 'POST') {
    const prefix = cleanKey((await body()).prefix);
    const meta = await readMeta(c);
    let changed = false;
    for (const k of Object.keys(meta)) if (k === prefix || k.startsWith(prefix + '/')) { delete meta[k]; changed = true; }
    if (changed) await writeMeta(c, meta);
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    // Fail closed: never serve the vault without a password
    if (!env.VAULT_PASSWORD) {
      return new Response('Set the VAULT_PASSWORD variable in Cloudflare first (Settings > Variables and Secrets).', { status: 500 });
    }
    if (!(await authOk(request, env.VAULT_PASSWORD))) {
      return new Response('Locked', { status: 401, headers: { 'WWW-Authenticate': 'Basic realm="Ashen Vault"' } });
    }
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    const missing = ['B2_ENDPOINT', 'B2_BUCKET', 'B2_KEY_ID', 'B2_APP_KEY'].filter((k) => !env[k]);
    if (missing.length) return json({ error: 'Missing variable(s): ' + missing.join(', ') }, 500);
    try {
      return await route(request, url, cfg(env));
    } catch (e) {
      return json({ error: e.message || 'Server error' }, e.status || 500);
    }
  },
};
