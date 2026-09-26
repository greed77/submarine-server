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

Layout: `cmd/submarine-server` (entry point and admin CLI), `internal/api` (HTTP handlers),
`internal/store` (all SQL, including schema migrations), `internal/secret` (tokens and
password hashing), `internal/mail`, `internal/config`.

## Roadmap

- A read-mostly admin web UI (users, storage, shares) on a separate listener, meant to sit
  behind Cloudflare Access. The storage stats it needs already exist (`store.UserStats`).
