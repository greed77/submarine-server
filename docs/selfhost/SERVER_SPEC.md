# Submarine Sync Server — Replacement Server Specification

**Purpose:** Everything needed to build a self-hostable, drop-in replacement for
the Submarine cloud-sync API (the upstream one runs at
`https://submarine.sinaxhpm.com`). The spec doesn't assume a language. It
describes the wire contract and the server-side behavior the client relies on.

**Status:** Worked out from the client source at upstream `v0.3.8`
(commit `b621516`). The upstream server (a PHP app the author calls
`mock-api/`) was never published, so this spec comes from (a) the client's
request/response types, (b) how the client *uses* each response, and
(c) server notes the author left in commit messages. Anything inferred rather
than read directly from code is marked **[inferred]**.

---

## 0. Reference material (the client repo)

If something here is ambiguous, the client code is the source of truth:

- Upstream: <https://github.com/sinaxhpm/submarine>
- Local fork on the author's machine: `D:\code\Submarine`, branch `feat/selfhost`
  (adds the "Sync server" setting described in §1).

Files worth reading:

| File | What's there |
|---|---|
| `src-tauri/src/cloud.rs` | **The whole HTTP transport.** Every endpoint, every request/response struct. Start here. |
| `src-tauri/src/lib.rs` | Sync engine + sharing logic that consumes responses. Key fns: `SyncRecord` (~L709), `collect_local_records`, `apply_entity` (client-side LWW), `sync_now` (~L1178), `build_pw_escrow_record`, `restore_personal_profile`, `share_current_profile`, `invite_to_share`, `rotate_share_dek`, `stop_sharing`, `force_push_profile`. |
| `src-tauri/src/hlc.rs` | Hybrid logical clock that produces `updated_at` stamps. |
| `src-tauri/src/identity.rs` | X25519 sealed-box + passphrase-wrap crypto (client-only; the server never touches it). |
| `src-tauri/src/cloud_config.rs` | (fork only) server URL override. |
| `src/components/CloudPanel.tsx` | Sign-up / sign-in / reset / magic-link UI flows. |
| `src/components/ProfilePanel.tsx`, `InvitesSection.tsx`, `ProfileSelectPage.tsx` | How share lists, member rosters, and cloud profile lists are displayed. |

Commits whose messages describe the original server's behavior:
`c0b8c1a` (reset + magic link), `c1f2a5a` (auth hardening), `64043ec` (`/sync`),
`724b0a2` (`/keys/*`), `03b4b11` + `942aa77` (`/shares/*`), `f73caec` (escrow),
`cef729b` (key rotation on revoke), `6d5aaae` (UUID partitions, `/sync/profiles`,
`/sync/delete`). Read them with `git show -s <hash>`.

---

## 1. How the client finds the server

- The base URL defaults to `https://submarine.sinaxhpm.com` (`CLOUD_API_BASE` in `cloud.rs`).
- In the fork, users can change it in **Cloud Sync panel → "Sync server: … Change"**.
  It's stored per-device in `<app_data>/cloud_server.json` as `{"url": "..."}`.
- The client requires `https://`. Plain `http://` is accepted only for `localhost`,
  `127.0.0.0/8` and `[::1]`, so run the dev server on loopback or put TLS in front of it.
- The URL may include a path prefix (`https://host/submarine`). The client builds each
  request URL as `base + "/auth/login"` and so on, so the server must work under a prefix if you deploy it that way.
- Changing the server URL signs the device out, so tokens never cross servers.
- The client talks to the server from **native Rust code (reqwest), not the webview**,
  so **CORS is irrelevant**.

---

## 2. Global conventions

### 2.1 Transport
- Request bodies are JSON (`Content-Type: application/json`). Responses must be JSON on
  every path the client parses (listed per endpoint).
- The client sends `User-Agent: submarine-app/<version>`.
- Client timeouts are 10 s to connect and 60 s per request. Keep `/sync` fast even for a few thousand records.
- The client ignores unknown response fields, so adding extra fields is always safe.
  **Missing required fields break the client** with `[CLOUD] BAD_RESPONSE`.

### 2.2 Authentication
- Auth is a bearer token in the custom header **`X-Auth-Token: <token>`**. It is *not*
  `Authorization` (the upstream host stripped that header). You may also accept
  `Authorization: Bearer`, but you **must** accept `X-Auth-Token`.
- Tokens are opaque, long-lived strings with no expiry the client knows about. The client
  stores them in `<app_data>/cloud_token.json`. Generate at least 256 bits of randomness
  and store only a hash (e.g. SHA-256) on the server.

### 2.3 Errors
- Any non-2xx response is an error. Preferred body:
  ```json
  { "error": "some_code", "message": "Human readable detail" }
  ```
  The client shows it as `[CLOUD] some_code: Human readable detail`. Both fields are
  optional. If the body isn't that JSON shape, the client shows the raw body text.
  The codes are free-form, because the client never branches on the code string.
- **Status codes with special meaning to the client:**
  - **`401` on any authenticated endpoint makes the client delete its token and sign the
    user out** ("SESSION_EXPIRED"). Return 401 **only** for a missing, invalid or revoked
    token. For "authenticated but not allowed", use **403**.
  - **`404` on `POST /keys/lookup`** means "no such shareable user", and the client handles it
    gracefully. See §5.3.
  - Everything else is treated as a generic failure.

### 2.4 Identifiers and formats

| Thing | Format as the client sends it | Server should accept |
|---|---|---|
| `user_id` | integer (JSON number, parsed as i64) | server-assigned integer |
| record `uuid` | 32 lowercase hex chars | 1–64 chars; treat as opaque |
| `entity_type` | `ssh_keys`, `folders`, `credentials`, `servers`, `commands`, `notes`, `monitor_configs`, `dek_escrow` | any string ≤ 24 chars; opaque |
| `updated_at` | HLC string `"{phys_ms:015}:{counter:05}:{node_id}"`, e.g. `001758899999123:00000:9f3a1c2b4d5e6f70` (38 chars); escrow uses the sentinel `000000000000000:00000:0` | ≤ 64 chars; compare **byte-wise as strings** |
| `blob` | lowercase hex of `nonce ‖ AES-GCM ciphertext` | hex text; allow at least ~1 MB per record (SSH private keys, notes) |
| personal partition `profile` | 32 hex (new profiles) **or** a legacy profile name (`[A-Za-z0-9_-]{1,32}`) | 1–64 chars |
| `share_id` | 32 hex | 16–64 chars (the upstream server enforced `{16,64}`) |
| share `name` | 1–64 chars (client-validated) | 1–64 chars |
| hex key material (`public_key`, `sealed_dek`, `enc_salt`, `wrapped_privkey`) | hex strings | store as opaque text; `wrapped_privkey` can be large, so allow ≤ 100 000 chars |
| email | trimmed by the client, case not normalized | **normalize (trim + lowercase)** on the server for lookup and uniqueness |

### 2.5 Zero-knowledge
The server never receives any decryption key. Blobs, sealed DEKs, wrapped private keys and
the escrow record are all opaque. **Never try to parse or validate their contents** beyond
size limits. The only plaintext metadata is `uuid`, `entity_type`, `updated_at`, `deleted`,
profile/share names and emails.

---

## 3. Suggested data model

This is the minimum state the behavior below needs. Adapt the names and types to your storage.

```
users            (id PK int, email UNIQUE (normalized), password_hash NULL,
                  created_at, failed_logins int, locked_until NULL)
auth_tokens      (token_hash PK, user_id FK, created_at, last_used_at)
email_tokens     (token_hash PK, user_id NULL, email, purpose ENUM('verify','claim','reset','login'),
                  expires_at, used_at NULL)
sync_records     (user_id, profile, uuid, entity_type, updated_at, deleted bool, blob NULL,
                  server_modified_at,  PK(user_id, profile, uuid))
sync_profile_names (user_id, profile, name, PK(user_id, profile))
user_keys        (user_id PK, public_key, wrapped_privkey, enc_salt, updated_at)
shares           (share_id PK, owner_user_id FK, name, created_at)
share_members    (share_id FK, user_id FK, role ENUM('owner','editor','user'),
                  status ENUM('pending','active'), sealed_dek, invited_at, accepted_at NULL,
                  PK(share_id, user_id))
shared_records   (share_id FK, uuid, entity_type, updated_at, deleted bool, blob NULL,
                  last_writer_user_id, server_modified_at, PK(share_id, uuid))
```

About the primary key on `uuid`: record uuids are random 128-bit values, or SHA-256-derived
with the table name mixed in (`derived_entity_uuid` in `lib.rs`). They don't collide across
entity types, so `(partition, uuid)` is a safe key. Keep `entity_type` as a column anyway,
because it comes back in responses.

---

## 4. Endpoints — Auth

All `/auth/*` endpoints are unauthenticated except `/auth/logout`.

### Flow overview
```
Sign-up:        POST /auth/signup {email}      → email contains VERIFY token
                GET  /auth/verify?token=V      → {claim_token, email}
                POST /auth/set-password        → {token, email}      (signed in)
Password login: POST /auth/login               → {token, email}
Forgot pw:      POST /auth/request-reset       → email contains RESET token
                POST /auth/reset-with-token    → {token, email}
Magic link:     POST /auth/request-login       → email contains LOGIN token
                POST /auth/login-with-link     → {token, email}
Logout:         POST /auth/logout  (X-Auth-Token)
```

**Emailed tokens are pasted into the app by hand.** The client has no deep-link handler.
An email can contain a clickable link (upstream used `reset_link_template` and similar),
but it **must also show the raw token** so the user can copy it. For self-hosting, make
email delivery optional: if SMTP isn't configured, log the token (or provide an admin CLI)
so sign-up works without mail.

### 4.1 `POST /auth/signup`
- **Request:** `{ "email": "a@b.c" }`
- **Response 200:** `{ "status": "<string>", "message": "<optional string>" }`. The client
  requires `status` to be a string but ignores its value (e.g. `"verification_sent"`).
- **Behavior:** create a single-use **verify** token (suggested TTL 24 h) tied to the email
  and send it. Respond the same way whether or not the email is already registered, so the
  endpoint can't be used to discover accounts. **[inferred]** For an already-registered,
  password-set email, either send nothing or send an "you already have an account; use
  reset" email. Don't let sign-up act as an unauthenticated password reset.
- Rate-limit per IP and per email.

### 4.2 `GET /auth/verify?token=<verify_token>`
- **Response 200:** `{ "claim_token": "<string>", "email": "<string>" }`
- **Behavior:** consume the verify token (single use; reject if expired or used), and issue a
  short-lived single-use **claim** token (suggested 30–60 min) bound to the email.
- **Errors:** 400/404/410 with an `{error,message}` body for invalid, expired or used tokens.

### 4.3 `POST /auth/set-password`
- **Request:** `{ "claim_token": "...", "password": "..." }`
- **Response 200:** `{ "token": "<bearer>", "email": "<string>" }`
- **Behavior:** consume the claim token, create the user (or set the password on a pending
  user), hash the password (Argon2id or bcrypt), and issue a bearer token.
  Password must be ≥ 8 chars (the client checks this too, but enforce it server-side).

### 4.4 `POST /auth/login`
- **Request:** `{ "email": "...", "password": "..." }`
- **Response 200:** `{ "token": "<bearer>", "email": "<string>" }`. Return the canonical stored email.
- **Errors:** wrong credentials → 401 or 400 with a generic message. (401 is safe here, because
  the sign-out-on-401 logic only runs on authenticated calls.) Upstream kept a
  failed-login counter with **account lockout**. For a locked account, return 403/429 with a
  generic message.
- Each login creates a new token. Multiple devices each hold their own token.

### 4.5 `POST /auth/logout`
- **Headers:** `X-Auth-Token`. **Body:** none.
- **Response:** any 2xx; the body is ignored. The client ignores failures entirely and clears
  its local token regardless.
- **Behavior:** revoke that one token.

### 4.6 `POST /auth/request-reset`
- **Request:** `{ "email": "..." }`
- **Response:** any 2xx; the body is ignored. **Always the same response** whether or not the email exists.
- **Behavior:** if the user exists, email a single-use **reset** token (upstream TTL 1 h).
  Rate-limit per IP and per email.

### 4.7 `POST /auth/reset-with-token`
- **Request:** `{ "reset_token": "...", "password": "..." }`
- **Response 200:** `{ "token": "<bearer>", "email": "<string>" }`
- **Behavior (upstream):** consume the token, set the new password (≥ 8), **revoke every existing
  bearer token for the user** (other devices get signed out), invalidate other outstanding reset
  tokens, clear the failed-login counter and lockout, then issue a fresh token.

### 4.8 `POST /auth/request-login`
- **Request:** `{ "email": "..." }`
- **Response:** any 2xx; the body is ignored. Same anti-enumeration rule as request-reset.
- **Behavior:** email a single-use **login** token (upstream TTL 15 min). **A locked account
  silently gets no email**, with the same response shape as an unknown email, so the magic link
  can't bypass lockout.

### 4.9 `POST /auth/login-with-link`
- **Request:** `{ "login_token": "..." }`
- **Response 200:** `{ "token": "<bearer>", "email": "<string>" }`
- **Behavior:** consume the token (single use) and issue a bearer token.

---

## 5. Endpoints — Personal sync

### 5.0 The record object (shared by `/sync` and `/shares/sync`)
```json
{
  "uuid": "3f9c...32hex",
  "entity_type": "servers",
  "updated_at": "001758899999123:00000:9f3a1c2b4d5e6f70",
  "deleted": false,
  "blob": "a1b2...hex"          // omitted when deleted=true; null also accepted
}
```
`uuid`, `entity_type`, `updated_at` and `deleted` are **required** in every returned record.
`blob` is optional (client default `null`).

### 5.1 `POST /sync` — the core exchange
- **Auth:** required.
- **Request:**
  ```json
  { "profile": "<partition>", "since": "", "records": [ ...record... ], "name": "Work" }
  ```
  `name` is **omitted** on pure pulls. Absent is different from empty: never overwrite a stored name with nothing.
- **Response 200:** `{ "records": [ ...record... ] }`
- **Behavior:**
  1. **Partition** = (authenticated user, `profile`). It is created implicitly on the first push.
     Users can only ever see their own partitions.
  2. **Merge each incoming record by Last-Write-Wins**, comparing `updated_at` **as byte
     strings**:
     - no stored row with that `uuid` → insert it.
     - stored row exists and **`incoming.updated_at >= stored.updated_at`** → replace the whole
       row (`entity_type`, `updated_at`, `deleted`, `blob`).
     - otherwise → keep the stored row and ignore the incoming one.

     ⚠️ **Replace on equal timestamps (`>=`), not only on newer ones (`>`).** Two client flows
     re-push *the same* `updated_at` with a *new* blob and depend on it being accepted:
     - **DEK rotation** after revoking a share member (`rotate_share_dek` in `lib.rs`): the owner
       re-encrypts every record under a new key and pushes it with unchanged stamps.
     - **Escrow refresh:** the `dek_escrow` record always carries the fixed stamp
       `000000000000000:00000:0` but its blob is re-sealed on every personal sync.

     **[inferred]**: the upstream code isn't available, but under strict `>` both flows would
     silently break. Equal HLC stamps from *different* edits can't happen, because the stamp
     includes a per-device node id, so `>=` is safe.
  3. **Tombstones** (`deleted: true`, no blob) are stored and returned like any other record.
     Never physically drop them during normal sync. A tombstone with a newer stamp replaces a live
     row, and a live row with a newer stamp replaces a tombstone.
  4. **Response** = every record in the partition with `updated_at > since`, taken **after** the
     merge (live records, tombstones, and the `dek_escrow` record). The client currently always
     sends `since: ""`, which means **return everything**. Order doesn't matter. Returning records
     the client just pushed is expected and harmless.
  5. If `name` is present and non-empty, upsert the partition's display name.
  6. **An empty `records` array is a pure read and must not change anything**, including not
     creating the partition or name row. The client relies on this for dry-run diffs
     (`profile_sync_stats`) and for restore peeks.
  7. Do the whole merge in one transaction.
- **The `dek_escrow` record** (`uuid` = `0000000000000000000000000000dead`,
  `entity_type` = `dek_escrow`) is an ordinary opaque record to the server. It is how a
  new device restores a profile with only its password
  (`restore_personal_profile`), so it **must** be stored and returned.

### 5.2 `GET /sync/profiles`
- **Auth:** required. **No body.**
- **Response 200:**
  ```json
  { "profiles": [
      { "profile": "3f9c...", "name": "Work", "records": 57, "live_records": 41,
        "last_updated": "2026-09-26T12:34:56Z" }
  ] }
  ```
  All five fields are required, except `name`, which defaults to `""` in the client but should always be sent.
- **Semantics:**
  - one entry per personal partition belonging to the caller.
  - `name` = the stored display name, or the `profile` string itself if none was recorded
    (legacy partitions were keyed by name).
  - `records` = total rows (live + tombstones + escrow).
  - `live_records` = rows with `deleted = false` **and** `entity_type != 'dek_escrow'`. The
    profile picker hides entries with `live_records == 0`.
  - `last_updated` = any string; it isn't displayed. Suggest the ISO-8601 time of the last server-side write.

### 5.3 `POST /sync/delete`
- **Auth:** required.
- **Request:** `{ "profile": "<partition>" }`
- **Response 200:** `{ "deleted": <int> }`, the number of rows removed.
- **Behavior:** hard-delete every row (data, tombstones, escrow) in the caller's partition, plus
  its display name. **A partition that doesn't exist returns `200 {"deleted": 0}`, not 404.**
  `force_push_profile` calls delete and then a full push, and must not fail on a never-synced profile.

---

## 6. Endpoints — Identity keys (for sharing)

Each account can publish one X25519 identity. The server stores it opaquely.

### 6.1 `POST /keys/publish`
- **Auth:** required.
- **Request:** `{ "public_key": "<64 hex>", "wrapped_privkey": "<hex>", "enc_salt": "<32 hex>" }`
- **Response 200:** `{ "created": <bool>, "rotated": <bool> }` (both **required**)
  - `created` = no key existed before.
  - `rotated` = a key existed and `public_key` changed.
- **Behavior:** upsert (the user deliberately overwrites via "reset identity"). Consider logging
  rotations. Grants sealed to the old key simply stop working, which is expected.

### 6.2 `GET /keys/me`
- **Auth:** required.
- **Response 200:**
  - with a key: `{ "exists": true, "public_key": "...", "wrapped_privkey": "...", "enc_salt": "..." }`
  - without: `{ "exists": false }` (the other fields may be omitted or `null`).

### 6.3 `POST /keys/lookup`
- **Auth:** required.
- **Request:** `{ "email": "..." }`
- **Response 200:** `{ "user_id": <int>, "email": "<canonical>", "public_key": "<hex>" }`
- **Response 404:** **the same response whether no such user exists or the user exists but has
  no published key**, so emails can't be enumerated. The client maps 404 to "that person hasn't set
  up sharing yet".
- Match email case-insensitively. Consider rate-limiting.

---

## 7. Endpoints — Shares

A **share** is a profile synced to a share-scoped record store (not the owner's personal
partition) and readable by several accounts. The owner generates a data key (DEK) and uploads a
**sealed copy per member** (`sealed_dek`, sealed to that member's public key). The server just
stores and returns each member's own sealed copy.

**Roles:** `owner` (exactly one, the creator), `editor` (read + write), `user` (read-only viewer).
**Member status:** `pending` (invited, not yet accepted) or `active`. The client only tests for
`status === "pending"` and `status != "revoked"`, so any string other than `pending` counts as
accepted. Use `active`.

**Every `/shares/*` endpoint is `POST` with a JSON body and requires auth.** Every one **must
return a JSON object**. Where the client expects `{ "ok": true }`, it parses the body, so an empty
body causes `BAD_RESPONSE` (`{}` also parses).

Authorization summary:

| Endpoint | Who may call |
|---|---|
| create | anyone (new share) / owner (existing share) |
| invite, set-role, revoke, delete | owner only → else 403 |
| list | any authed user (returns own memberships) |
| dek, members, accept | a member of that share (pending or active) → else 403/404 |
| leave | a non-owner member → else 403/400 |
| sync | active member (or owner); pushes need owner/editor |

### 7.1 `POST /shares/create`
- **Request:** `{ "share_id": "<32 hex>", "name": "...", "sealed_dek": "<hex>" }`
- **Response 200:** `{ "ok": true }`
- **Behavior. This is an upsert, and the client depends on that:**
  - `share_id` unknown → create the share with the caller as owner, and add a member row
    `(caller, role=owner, status=active, sealed_dek)`.
  - `share_id` exists **and the caller is its owner** → update `name` and the owner's `sealed_dek`.
    Key rotation calls create again for this.
  - exists and the caller is not the owner → 403.

### 7.2 `POST /shares/invite`
- **Request:** `{ "share_id": "...", "email": "...", "role": "editor"|"user", "sealed_dek": "<hex>" }`
- **Response 200:** `{ "member_user_id": <int> }` (**required**)
- **Behavior (upsert):**
  - owner only; `role` must be `editor` or `user` (400 otherwise).
  - resolve the email to a user (404 if unknown).
  - no membership → insert `(role, status=pending, sealed_dek)`.
  - **existing membership → replace `sealed_dek` (and `role`) but keep `status`.** Key rotation
    re-invites every existing member with a new sealed key and must not reset active members to pending.
  - inviting the owner themselves → 400.

### 7.3 `POST /shares/list`
- **Request:** `{}`
- **Response 200:**
  ```json
  { "shares": [ { "share_id": "...", "name": "...", "role": "owner|editor|user",
                  "status": "pending|active", "owner_email": "..." } ] }
  ```
- Returns every share the caller belongs to, **including ones they own** (role `owner`) and
  pending invites. The UI filters out owned ones for the "incoming invites" list.

### 7.4 `POST /shares/dek`
- **Request:** `{ "share_id": "..." }`
- **Response 200:** `{ "role": "...", "status": "...", "sealed_dek": "<hex>" }`
- The caller's **own** membership grant. The client calls this before **every** shared sync to pick
  up key rotations, so make it cheap (a primary-key lookup). Not a member → 403 or 404.

### 7.5 `POST /shares/members`
- **Request:** `{ "share_id": "..." }`
- **Response 200:** `{ "members": [ { "user_id": <int>, "email": "...", "role": "...", "status": "..." } ] }`
- Full roster including the owner. The caller must be a member. **Don't include revoked members**
  (see §7.8). The UI shows every returned row.

### 7.6 `POST /shares/accept`
- **Request:** `{ "share_id": "..." }`
- **Response 200:** `{ "role": "...", "sealed_dek": "<hex>" }`
- The caller's membership changes from `pending` to `active`. **Idempotent** if already active.
  No membership → 404/403.

### 7.7 `POST /shares/set-role`
- **Request:** `{ "share_id": "...", "member_user_id": <int>, "role": "editor"|"user" }`
- **Response 200:** `{ "ok": true }`
- Owner only. Changing the owner's own role, or targeting a non-member → 400/404.

### 7.8 `POST /shares/revoke`
- **Request:** `{ "share_id": "...", "member_user_id": <int> }`
- **Response 200:** `{ "ok": true }`
- Owner only; the owner can't be revoked. **Delete the membership row**, which takes effect
  immediately for `/shares/sync`, `/shares/dek` and the rest. A later re-invite starts fresh as
  `pending`. (If you keep the row with `status='revoked'` instead, exclude it from `list`,
  `members`, `dek` and `sync`, and let invite reset it to `pending`.)
- The client then rotates the key: `create` (owner re-seal), then `members`, then `lookup` + `invite`
  for each remaining member, then a full re-push with **identical `updated_at` stamps**. This is why §5.1 requires `>=`.

### 7.9 `POST /shares/leave`
- **Request:** `{ "share_id": "..." }`
- **Response 200:** `{ "ok": true }`
- A non-owner removes their own membership. Owner → 400 ("delete the share instead").
  Non-member → 403/404. The client tolerates this failure and clears its local state anyway.

### 7.10 `POST /shares/delete`
- **Request:** `{ "share_id": "..." }`
- **Response 200:** `{ "ok": true }`
- Owner only. Delete the share, **all memberships, and all its shared records**.

### 7.11 `POST /shares/sync`
- **Request:** `{ "share_id": "...", "since": "", "records": [ ...record... ] }` (no `name` field)
- **Response 200:** `{ "records": [ ...record... ] }`
- **Exactly the same merge and response rules as §5.1**, but the partition is `share_id` in `shared_records`.
- **Access:**
  - the caller must be an **active** member (the owner is always active). Otherwise 403.
  - **role `user` with non-empty `records` → 403** `{"error":"read_only",...}`. An empty push (pull) is fine.
  - owner and editor may push.
- Store `last_writer_user_id` on each written row. The client doesn't read it, but it's useful for auditing.
- There is no escrow record in shares. Members get the key through `sealed_dek`.

---

## 8. Things the client does NOT use (out of scope)

- Legacy whole-vault blob endpoints (`/profiles`, `/blobs`, …) were removed from the client in `f73caec`.
- The upstream browser **account dashboard** (`/account/`, mentioned in the README) isn't called
  by the app. It's optional.
- Upstream had Cloudflare-specific origin checks (`CF-Ray`, `CF-Connecting-IP`). They don't matter
  for self-hosting, except: if you run behind a reverse proxy, take the client IP from the proxy
  header for rate limiting.

---

## 9. Operational recommendations

- **TLS is mandatory** outside loopback (the client refuses plain http). A reverse proxy
  (Caddy, nginx or Traefik) in front of a plain-HTTP app server is fine.
- **Request body limit:** a full-profile `/sync` push carries every record hex-encoded. Allow at
  least ~20 MB and make it configurable.
- **Rate limiting** on the auth endpoints (signup, login, request-reset, request-login, lookup).
- **Periodic cleanup** of expired email tokens. Upstream ran `cron.php`; an in-process timer is fine.
- **Self-hosting niceties** (not required by the client): an option to disable open signup or
  allowlist emails; an admin CLI to create users, reset passwords and print tokens when email isn't
  configured; `GET /health` for monitoring.
- **Backups:** the database is all ciphertext plus account metadata, so back it up like any other DB.

---

## 10. End-to-end acceptance tests

Point a client at the server (Cloud Sync panel → Sync server → e.g. `http://localhost:8080`) and verify:

1. **Sign-up:** signup → token appears (email or log) → paste → set password → signed in.
2. **Login / logout / magic link / reset:** each yields a working token. After a reset, the other device's next call gets 401 and it signs out.
3. **Personal sync, two devices (same account):** add a server on A → sync → sync on B → it appears. Edit on B, delete on A, and confirm the changes and the tombstone propagate.
4. **Restore on a new device:** on B, the profile picker lists A's cloud profile (from `/sync/profiles`). Restore it with the profile password. This needs the `dek_escrow` record to come back from `/sync`.
5. **Dry run doesn't write:** the Profile panel's sync stats (empty push) leave the DB unchanged.
6. **Force push:** `/sync/delete` then a full push repopulates the partition. Delete on a never-synced partition returns `{deleted:0}`.
7. **Sharing (two accounts X and Y):** both set up an identity (`/keys/publish`). X shares a profile and invites Y as editor. Y accepts and imports. Edits flow both ways. Downgrade Y to viewer: Y's pull works and push gets 403 `read_only`.
8. **Revoke + rotation:** add a third account Z, then revoke Y. Y gets 403. Z keeps syncing **and can still decrypt** after X's next sync. This only passes with equal-stamp replacement (§5.1).
9. **Stop sharing:** the owner deletes the share, which cascades. A member leaves and disappears from the roster.
10. **401 hygiene:** a bogus `X-Auth-Token` gives 401 on authenticated routes. A viewer push gives **403, not 401**. The client must not get signed out for permission errors.

### Handy curl smoke tests
```sh
B=http://localhost:8080
curl -s -XPOST $B/auth/login -H 'content-type: application/json' \
     -d '{"email":"a@b.c","password":"hunter22"}'
T=<token>
curl -s -XPOST $B/sync -H "X-Auth-Token: $T" -H 'content-type: application/json' \
     -d '{"profile":"0123456789abcdef0123456789abcdef","since":"","records":[
          {"uuid":"aa","entity_type":"notes","updated_at":"001758899999123:00000:01","deleted":false,"blob":"00ff"}],
          "name":"Test"}'
curl -s $B/sync/profiles -H "X-Auth-Token: $T"
```
