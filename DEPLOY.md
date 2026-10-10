# Ashen Vault: deploy guide

Cloudflare serves the page and a small Worker API. Backblaze B2 stores the files. A D1 database (free) stores the file list.

```
browser ──► Cloudflare Worker (login, file list, signs links) ──► D1
   │                       │
   │  upload (signed URL)  └── downloads stream through the Worker
   └──────────────► Backblaze B2 (private bucket)
```

## 1. Backblaze B2

1. Keep your bucket **Private**.
2. On the bucket page, copy the **S3 Endpoint** (looks like `s3.us-west-004.backblazeb2.com`).
3. **Application Keys → Add a New Application Key**: restrict it to your bucket, access **Read and Write**. Copy the `keyID` and `applicationKey` now; the key is shown only once.
4. **Bucket Settings → CORS Rules → custom rules** (needed so the browser can upload straight to B2). Add one rule:
   - Origin: your site URL, e.g. `https://ashen-vault.YOURNAME.workers.dev` (add your custom domain later if you use one; add `http://localhost:8787` only if you test locally)
   - Allowed operations: **S3 PUT**
   - Allowed headers: `*`
   - Max age: `3600`

   The B2 CORS screen has changed before. If yours differs, check Backblaze's CORS docs. The goal is "S3 API PUT from your origin, any header".

## 2. Install

```bash
cd ashen-vault
npm install
npx wrangler login
```

## 3. Database

```bash
npx wrangler d1 create ashen-vault
```

Copy the printed `database_id` into `wrangler.toml`, then:

```bash
npm run db:init
```

## 4. Settings

In `wrangler.toml` set `B2_ENDPOINT` and `B2_BUCKET`.

## 5. Deploy

```bash
npm run deploy
```

Wrangler prints your URL (`https://ashen-vault.<you>.workers.dev`). Put that exact origin in the B2 CORS rule from step 1.

## 6. Secrets

```bash
npx wrangler secret put VAULT_PASSWORD     # your login password (make it long)
npx wrangler secret put SESSION_SECRET     # paste output of: openssl rand -hex 32
npx wrangler secret put B2_KEY_ID
npx wrangler secret put B2_APP_KEY
```

Open the URL and sign in. Upload a small file first to confirm CORS is right. If uploads fail with "Upload blocked", it's the CORS rule.

## Local testing (optional)

```bash
cp .dev.vars.example .dev.vars    # fill it in
npm run db:init:local
npm run dev                       # http://localhost:8787
```

## Notes

- **Limits:** 5 GB per file (single upload). The vault refuses new uploads past 10 GB (counts trashed files until they're deleted forever).
- **Free plan:** Workers Free allows 100,000 requests/day. Static page loads are free and unlimited. Image thumbnails and downloads go through the Worker, so a huge grid of images costs requests.
- **Egress:** downloads stream B2 → Worker → you. B2 advertises free egress to Cloudflare through the Bandwidth Alliance, but check Backblaze's current terms for your account.
- **Security:** one shared password, 7-day login cookie, lockout after 8 wrong tries per IP per 15 minutes. Share links are long unguessable URLs (`/s/<token>`) that anyone with the link can download; "stop sharing" revokes one. If your B2 key ever leaks, delete it in B2 and make a new one.
- **Not included:** folder sharing, moving files between folders, multipart upload for resuming huge files.
