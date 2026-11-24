/**
 * SQLite 結構（node:sqlite，WAL）。
 * message_fts 使用 FTS5 trigram，可直接搜尋中文；少於 3 字元的查詢改用 instr()。
 */
export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- LINEJS BaseStorage（token、憑證、E2EE 金鑰）；絕不經 MCP 暴露
CREATE TABLE IF NOT EXISTS line_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- App 設定（read_receipts、sync_scope ...）
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS chat (
  id              TEXT PRIMARY KEY,           -- LINE MID（u/c/r 開頭）
  type            TEXT NOT NULL,              -- USER | GROUP | ROOM | SQUARE
  name            TEXT,
  member_count    INTEGER,
  last_message_at INTEGER,                    -- epoch ms
  allowed         INTEGER NOT NULL DEFAULT 0, -- 1 = 允許 AI / MCP 存取（白名單）
  ai_mode         TEXT NOT NULL DEFAULT 'off',-- off | suggest | auto（階段 5）
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS participant (
  mid          TEXT PRIMARY KEY,
  display_name TEXT
);

CREATE TABLE IF NOT EXISTS message (
  chat_id       TEXT NOT NULL REFERENCES chat(id),
  id            TEXT NOT NULL,                -- 十進位字串，絕不轉成 JS number
  sender_mid    TEXT,
  from_self     INTEGER NOT NULL DEFAULT 0,
  sent_at       INTEGER NOT NULL,             -- epoch ms
  content_type  TEXT NOT NULL DEFAULT 'NONE', -- NONE(文字) | IMAGE | VIDEO | AUDIO | FILE | STICKER ...
  text          TEXT,
  media_name    TEXT,
  media_size    INTEGER,
  decrypt_state TEXT NOT NULL DEFAULT 'plain',-- plain | decrypted | missing_key | invalid
  meta_json     TEXT,                         -- contentMetadata（不含 chunks）
  PRIMARY KEY (chat_id, id)
);
CREATE INDEX IF NOT EXISTS message_by_time ON message(chat_id, sent_at);

CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
  text, content='message', content_rowid='rowid', tokenize='trigram'
);
CREATE TRIGGER IF NOT EXISTS message_ai AFTER INSERT ON message BEGIN
  INSERT INTO message_fts(rowid, text) VALUES (new.rowid, new.text);
END;
CREATE TRIGGER IF NOT EXISTS message_ad AFTER DELETE ON message BEGIN
  INSERT INTO message_fts(message_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
END;
CREATE TRIGGER IF NOT EXISTS message_au AFTER UPDATE OF text ON message BEGIN
  INSERT INTO message_fts(message_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
  INSERT INTO message_fts(rowid, text) VALUES (new.rowid, new.text);
END;

-- 本帳號在每個會話的已讀位置（只讀取，不回寫 LINE）
CREATE TABLE IF NOT EXISTS read_state (
  chat_id              TEXT PRIMARY KEY REFERENCES chat(id),
  last_read_message_id TEXT,
  last_read_at         INTEGER
);

CREATE TABLE IF NOT EXISTS media (
  chat_id       TEXT NOT NULL,
  message_id    TEXT NOT NULL,
  path          TEXT NOT NULL,
  mime          TEXT,
  size          INTEGER,
  downloaded_at INTEGER NOT NULL,
  PRIMARY KEY (chat_id, message_id)
);

CREATE TABLE IF NOT EXISTS sync_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;
