/**
 * SQLite 結構（node:sqlite，WAL）。
 * message_fts 使用 FTS5 trigram，可直接搜尋中文；少於 3 字元的查詢改用 instr()。
 */
export const SCHEMA_VERSION = 2;

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

-- ===== 階段 5：AI 代聊 =====
-- 每個會話的 AI 設定。沒有資料列 = 全部關閉（安全預設）。只有白名單會話能生效。
CREATE TABLE IF NOT EXISTS chat_ai (
  chat_id          TEXT PRIMARY KEY REFERENCES chat(id),
  ai_allowed       INTEGER NOT NULL DEFAULT 0,     -- AI 代聊白名單（與 MCP 白名單分開；兩者都要勾）
  mode             TEXT    NOT NULL DEFAULT 'off', -- off | suggest（僅建議回覆）| auto（AI 代聊）
  style_lieflat    INTEGER NOT NULL DEFAULT 1,     -- 去 AI 味檢查 / 改寫（預設開）
  allow_image      INTEGER NOT NULL DEFAULT 0,     -- 允許生成圖片並發送
  confirm_send     INTEGER NOT NULL DEFAULT 1,     -- 發送前確認（預設開）
  min_interval_sec INTEGER NOT NULL DEFAULT 300,   -- 兩次 AI 發送最短間隔
  delay_sec        INTEGER NOT NULL DEFAULT 30,    -- 自動回覆延遲
  max_per_hour     INTEGER NOT NULL DEFAULT 4,
  max_per_day      INTEGER NOT NULL DEFAULT 10,
  active_start     INTEGER,                         -- 活躍時段（當地分鐘 0-1439）；NULL = 不限
  active_end       INTEGER,
  updated_at       INTEGER NOT NULL
);

-- 待送 / 已送 / 被拒的 AI 訊息（確認佇列）
CREATE TABLE IF NOT EXISTS outbox (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id       TEXT    NOT NULL,
  kind          TEXT    NOT NULL,              -- text | image | sticker
  text          TEXT,                          -- 文字內容或圖片說明
  sticker_json  TEXT,                          -- {"package_id","sticker_id","version"}
  prompt        TEXT,                          -- 圖片提示詞
  image_path    TEXT,
  origin        TEXT    NOT NULL,              -- auto | suggest | mcp | ui
  origin_detail TEXT,                          -- 例如 MCP client 名稱
  reply_to      TEXT,                          -- 引用回覆的訊息 id（LINE relatedMessageId）
  trigger_id    TEXT,                          -- 觸發自動回覆的訊息 id
  status        TEXT    NOT NULL,              -- pending | approved | sent | rejected | failed | expired
  flags         TEXT,                          -- injection_suspected,...
  created_at    INTEGER NOT NULL,
  scheduled_at  INTEGER,
  decided_at    INTEGER,
  sent_at       INTEGER,
  mentions_json TEXT,                          -- 反詐提醒 @ 管理員：[{start,end,mid}]
  error         TEXT
);
CREATE INDEX IF NOT EXISTS outbox_status ON outbox(status, scheduled_at);

-- 稽核紀錄（不含祕密；訊息內容截斷）
CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  actor   TEXT    NOT NULL,                    -- ui | mcp | auto | system
  action  TEXT    NOT NULL,
  chat_id TEXT,
  ok      INTEGER NOT NULL DEFAULT 1,
  detail  TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);

-- ===== 群組反詐 =====
-- 範例庫：內建（來自 anti-scam-helper，Apache-2.0）＋ 使用者 / MCP 新增
CREATE TABLE IF NOT EXISTS scam_sample (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  label      TEXT    NOT NULL,                 -- SCAM | OK
  category   TEXT    NOT NULL,
  text       TEXT    NOT NULL,
  source     TEXT    NOT NULL,                 -- builtin | user | mcp
  created_at INTEGER NOT NULL,
  UNIQUE(label, text)
);
-- 警示：只標記，不回覆、不採取任何動作
CREATE TABLE IF NOT EXISTS scam_alert (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id      TEXT    NOT NULL,
  message_id   TEXT    NOT NULL,
  score        INTEGER NOT NULL,
  level        TEXT    NOT NULL,              -- suspicious | high
  rules        TEXT    NOT NULL,              -- JSON 陣列：命中規則
  sample_id    INTEGER,                       -- 最相似的 SCAM 範例
  similarity   REAL,
  ai_verdict   TEXT,                          -- scam | suspicious | ok | NULL（沒有 AI 判讀）
  ai_reason    TEXT,
  status       TEXT    NOT NULL DEFAULT 'new',-- new | seen | dismissed
  category     TEXT,                          -- 詐騙類型（假搬家群、投資飆股帶單…）
  created_at   INTEGER NOT NULL,
  UNIQUE(chat_id, message_id)
);
CREATE INDEX IF NOT EXISTS scam_alert_ts ON scam_alert(created_at);

-- 反詐即時提醒（每群組；預設關）
CREATE TABLE IF NOT EXISTS scam_warn (
  chat_id      TEXT PRIMARY KEY REFERENCES chat(id),
  enabled      INTEGER NOT NULL DEFAULT 0,
  min_level    TEXT    NOT NULL DEFAULT 'high', -- high | suspicious
  cooldown_min INTEGER NOT NULL DEFAULT 30,     -- 同一發送者＋同類型多久內不重複提醒
  daily_cap    INTEGER NOT NULL DEFAULT 10,
  mention_admins INTEGER NOT NULL DEFAULT 1,    -- 提醒時 @ 這群的管理員
  template     TEXT,                            -- NULL = 用全域範本
  updated_at   INTEGER NOT NULL
);

-- 每群組的管理員／信任成員：不掃描他們的訊息；mention=1 的人會在提醒裡被 @（最多 3 位）
CREATE TABLE IF NOT EXISTS scam_admin (
  chat_id  TEXT NOT NULL,
  mid      TEXT NOT NULL,
  name     TEXT,
  mention  INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (chat_id, mid)
);

-- 社群貼文草稿（只存草稿，App 不會發布）
CREATE TABLE IF NOT EXISTS social_draft (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id     TEXT,
  platform    TEXT    NOT NULL,
  mode        TEXT    NOT NULL,
  text        TEXT    NOT NULL,
  warnings    TEXT,
  created_at  INTEGER NOT NULL
);
`;
