CREATE TABLE IF NOT EXISTS items (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL CHECK (type IN ('file', 'folder')),
  parent      TEXT,
  size        INTEGER NOT NULL DEFAULT 0,
  mime        TEXT,
  b2_key      TEXT,
  star        INTEGER NOT NULL DEFAULT 0,
  trash       INTEGER NOT NULL DEFAULT 0,
  share_token TEXT UNIQUE,
  status      TEXT NOT NULL DEFAULT 'ready',   -- 'pending' until the upload is confirmed
  mod         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_parent ON items(parent);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip, ts);
