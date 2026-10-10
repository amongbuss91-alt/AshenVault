// Minimal AWS Signature V4 query-string presigner (works with Backblaze B2's S3-compatible API).
// Uses only WebCrypto, so it runs in Cloudflare Workers and Node 19+ with no dependencies.

const enc = new TextEncoder();

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hmac(key, data) {
  const k = await crypto.subtle.importKey(
    'raw',
    typeof key === 'string' ? enc.encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return crypto.subtle.sign('HMAC', k, enc.encode(data));
}

async function sha256hex(s) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

// RFC 3986 encoding, as SigV4 requires
export const uriEncode = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

/**
 * Build a presigned URL.
 * @param {object} o
 * @param {string} o.method   HTTP method (GET, PUT, HEAD, DELETE)
 * @param {string} o.host     e.g. s3.us-west-004.backblazeb2.com
 * @param {string} o.path     already-encoded absolute path, e.g. /bucket/f/abc
 * @param {string} o.region   e.g. us-west-004
 * @param {string} o.keyId
 * @param {string} o.secret
 * @param {number} [o.expires=900] seconds
 * @param {Date}   [o.now]
 */
export async function sigv4Presign({ method, host, path, region, keyId, secret, expires = 900, now = new Date() }) {
  const amz = now.toISOString().replace(/[:-]|\.\d{3}/g, ''); // 20260101T000000Z
  const date = amz.slice(0, 8);
  const scope = `${date}/${region}/s3/aws4_request`;

  const params = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${keyId}/${scope}`,
    'X-Amz-Date': amz,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': 'host',
  };
  const qs = Object.keys(params)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(params[k])}`)
    .join('&');

  const canonical = [method, path, qs, `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', amz, scope, await sha256hex(canonical)].join('\n');

  const kDate = await hmac('AWS4' + secret, date);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, 's3');
  const kSigning = await hmac(kService, 'aws4_request');
  const signature = hex(await hmac(kSigning, toSign));

  return `https://${host}${path}?${qs}&X-Amz-Signature=${signature}`;
}
