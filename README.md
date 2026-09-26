# submarine-server

A self-hostable sync server for the [Submarine](https://github.com/sinaxhpm/submarine)
SSH client: a single Go binary and a SQLite file, shipped as a ~12 MB `FROM scratch`
container for amd64 and arm64 (Raspberry Pi).

It implements the wire contract in [`docs/selfhost/SERVER_SPEC.md`](docs/selfhost/SERVER_SPEC.md):
accounts, personal profile sync, identity keys and shared profiles. The server is
zero-knowledge. It stores only ciphertext it can't decrypt, plus emails, profile/share
names and record metadata.

## Quick start

```sh
docker build -t submarine-server .
docker run -d --name submarine -p 127.0.0.1:8080:8080 -v submarine-data:/data submarine-server
docker exec submarine /submarine-server user create you@example.com
```

`user create` prints a one-time code. In the app, open **Cloud Sync → Sync server → Change**,
enter your server URL, then **Sign in → Forgot password → "Already have a reset token?
Continue"**. Paste the code and choose a password.

The client requires HTTPS except on `localhost`, so put it behind a TLS proxy or a tunnel.
[`compose.example.yml`](compose.example.yml) runs it behind a Cloudflare Tunnel whose
cloudflared runs on the host, with the port bound to loopback.

### Behind Cloudflare

- **Don't put Cloudflare Access, Bot Fight Mode or other challenges in front of the API
  hostname.** The app is a native client, not a browser. A challenge page shows up in the
  app as `BAD_RESPONSE`.
- Set `TRUST_PROXY_HEADER=CF-Connecting-IP` so rate limits see real client IPs. Only do
  this if the container is reachable *only* through the tunnel, e.g. published on
  `127.0.0.1` as in the example. If the port is open to the LAN, anyone on the LAN can
  forge the header.
- Cloudflare's 100 MB request-body limit is above the server's 20 MB default, and its
  100 s timeout is longer than the client's 60 s.

## Configuration

All settings come from environment variables.

| Variable | Default | |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | |
| `DB_PATH` | `/data/submarine.db` in the image, `data/submarine.db` otherwise | |
| `BASE_PATH` | *(empty)* | Serve under a prefix, e.g. `/submarine` |
| `SIGNUP` | `allowlist` | `open`, `allowlist` (only emails added with `allow add`), or `closed` (accounts only via `user create`) |
| `TRUST_PROXY_HEADER` | *(empty)* | Header holding the real client IP, e.g. `CF-Connecting-IP` |
| `MAX_BODY_MB` | `20` | Largest request (a full-profile push) |
| `MAX_RECORD_MB` | `4` | Largest single record, decoded |
| `SERVER_NAME` | `Submarine Sync` | Used in email subjects |
| `SMTP_HOST` | *(empty)* | Without it, emailed codes are written to the log instead |
| `SMTP_PORT` | `587` | |
| `SMTP_SECURITY` | `starttls` | `starttls`, `tls` (implicit, usually port 465) or `none` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | | |
| `SMTP_FROM` | | Required when `SMTP_HOST` is set |
| `ADMIN_ADDR` | *(empty)* | Listen address for the admin web UI inside the container, e.g. `:8081`. It's off when empty. To use a different host port, change the Docker port mapping (`-p 127.0.0.1:9081:8081`), not this setting |
| `CF_ACCESS_TEAM_DOMAIN` | | Admin auth through Cloudflare Access: your team name or `<team>.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | | The Access application's audience (AUD) tag |
| `ADMIN_PASSWORD` | | Admin auth by HTTP basic auth (any username) |
| `ADMIN_INSECURE_NO_AUTH` | | `true` to run the admin UI with no auth at all (only if the port is private to you) |

## Admin web UI

Set `ADMIN_ADDR` to get a web page for managing the server:
- **Users:** everyone's storage use, last-seen time, devices and status.
- **Per-user page:** their profiles and shares, plus a signed-in-devices list.
- **Actions:** create users, hand out password-reset and sign-in codes, sign out all devices,
  disable accounts, and delete users or shares.
- **Sign-up:** manage the allowlist.

The server never has the keys, so the UI shows sizes and counts, never the contents of anyone's data.

It runs on its own port, separate from the API, and it won't start without authentication:

- **Cloudflare Access (recommended):** give the admin port its own tunnel hostname, create
  an Access application for that hostname, and set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD`
  (in Zero Trust → Access → Applications → your app → *Application Audience (AUD) Tag*).
  The server checks the Access token's signature itself, so reaching the port without going
  through Cloudflare doesn't get anyone in. Admin actions are logged with the Access email.
- **Password:** set `ADMIN_PASSWORD` for browser basic auth. After 10 wrong passwords in a
  minute, the UI refuses logins for a minute. You can set this together with Access.

All forms are protected against cross-site requests, and deletes require typing the user's
email or the share's name to confirm.

## Admin CLI

Run against the same database, including while the server is running:
`docker exec submarine /submarine-server <command>`.

```
user list                     users, last seen, devices, record counts, storage used
user create <email>           create a user and print a password-setup code
user reset-token <email>      print a password reset code (valid 24 h)
user login-token <email>      print a one-time sign-in code (valid 1 h)
user signout <email>          revoke every session
user disable | enable <email> block/unblock (disable also signs out every device)
user delete <email>           delete a user, their data and the shares they own
allow list | add | remove     manage the sign-up allowlist
backup <file>                 consistent snapshot of the database
```

## Backups

Everything lives in one SQLite file in `/data`. To take a consistent copy while the
server is running:

```sh
docker exec submarine /submarine-server backup /data/backup-$(date +%F).db
```

The database is ciphertext plus account metadata, so back it up like any other database.
Don't copy `submarine.db` directly while the server is running; its WAL file may hold
recent writes.

## Security behavior

- Bearer tokens are 256-bit random values. Only their SHA-256 is stored. Passwords use Argon2id.
- **401 means "your token is bad"**, and the client signs out when it gets one. Permission
  errors are always 403.
- Failed password logins back off exponentially per *(email, IP)* after 5 attempts. There is
  deliberately no hard account lockout, so a stranger can't lock the real owner out.
- Sign-up, reset and magic-link requests respond the same way whether or not an account
  exists, and `/keys/lookup` returns the same 404 for unknown users and users without keys.

## Development

Go isn't required locally. The toolchain can run in Docker:

```sh
docker run --rm -v "$PWD:/src" -v submarine-gomod:/go/pkg/mod -w /src golang:1-alpine go test ./...
```

The tests in `internal/api/api_test.go` are HTTP-level contract tests, one per client-visible
behavior in the spec. The most important one is equal-stamp replacement (`>=`) in the sync
merge, which key rotation and escrow refresh depend on.

Layout: `cmd/submarine-server` (entry point and admin CLI), `internal/api` (sync API
handlers), `internal/admin` (admin web UI: templates and CSS are embedded), `internal/store`
(all SQL, including schema migrations), `internal/secret` (tokens and password hashing),
`internal/mail`, `internal/config`.
