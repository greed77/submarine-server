package store

// migrations are applied in order; PRAGMA user_version records how many have
// run. Never edit a shipped migration — append a new one.
//
// All times are Unix milliseconds. updated_at columns hold the client's HLC
// strings and are compared byte-wise (SQLite's default BINARY collation).
// blob_bytes is the decoded size of the hex blob, kept so storage stats never
// have to scan blob contents.
var migrations = []string{
	`
CREATE TABLE users (
	id            INTEGER PRIMARY KEY,
	email         TEXT    NOT NULL UNIQUE,
	password_hash TEXT,
	created_at    INTEGER NOT NULL,
	last_seen_at  INTEGER,
	disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE auth_tokens (
	token_hash   BLOB    PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL
);
CREATE INDEX auth_tokens_user ON auth_tokens(user_id);

CREATE TABLE email_tokens (
	token_hash BLOB    PRIMARY KEY,
	email      TEXT    NOT NULL,
	purpose    TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER
);
CREATE INDEX email_tokens_email ON email_tokens(email, purpose);

CREATE TABLE signup_allowlist (
	email    TEXT    PRIMARY KEY,
	added_at INTEGER NOT NULL
);

CREATE TABLE sync_records (
	user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	profile            TEXT    NOT NULL,
	uuid               TEXT    NOT NULL,
	entity_type        TEXT    NOT NULL,
	updated_at         TEXT    NOT NULL,
	deleted            INTEGER NOT NULL,
	blob               TEXT,
	blob_bytes         INTEGER NOT NULL,
	server_modified_at INTEGER NOT NULL,
	PRIMARY KEY (user_id, profile, uuid)
);

CREATE TABLE sync_profile_names (
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	profile TEXT    NOT NULL,
	name    TEXT    NOT NULL,
	PRIMARY KEY (user_id, profile)
);

CREATE TABLE user_keys (
	user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	public_key      TEXT    NOT NULL,
	wrapped_privkey TEXT    NOT NULL,
	enc_salt        TEXT    NOT NULL,
	updated_at      INTEGER NOT NULL
);

CREATE TABLE shares (
	share_id      TEXT    PRIMARY KEY,
	owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name          TEXT    NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE INDEX shares_owner ON shares(owner_user_id);

CREATE TABLE share_members (
	share_id    TEXT    NOT NULL REFERENCES shares(share_id) ON DELETE CASCADE,
	user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role        TEXT    NOT NULL,
	status      TEXT    NOT NULL,
	sealed_dek  TEXT    NOT NULL,
	invited_at  INTEGER NOT NULL,
	accepted_at INTEGER,
	PRIMARY KEY (share_id, user_id)
);
CREATE INDEX share_members_user ON share_members(user_id);

CREATE TABLE shared_records (
	share_id            TEXT    NOT NULL REFERENCES shares(share_id) ON DELETE CASCADE,
	uuid                TEXT    NOT NULL,
	entity_type         TEXT    NOT NULL,
	updated_at          TEXT    NOT NULL,
	deleted             INTEGER NOT NULL,
	blob                TEXT,
	blob_bytes          INTEGER NOT NULL,
	last_writer_user_id INTEGER,
	server_modified_at  INTEGER NOT NULL,
	PRIMARY KEY (share_id, uuid)
);
`,
}
