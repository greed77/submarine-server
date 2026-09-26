# submarine-server

Go + SQLite reimplementation of the Submarine sync API. `docs/selfhost/SERVER_SPEC.md` is the contract; the client source (`D:\code\Submarine`, `src-tauri/src/cloud.rs`) is the tiebreaker.

- Go is **not installed** on the dev box. Run the toolchain in Docker (from Git Bash, set `MSYS_NO_PATHCONV=1`, otherwise container paths like `/src` get rewritten):
  `docker run --rm -v "D:/code/submarine-server:/src" -v submarine-gomod:/go/pkg/mod -v submarine-gocache:/root/.cache/go-build -w /src golang:1-alpine go test ./...`
  Use the `golang:1` (Debian) image for `go test -race`, since alpine has no cgo.
- All SQL lives in `internal/store`. Handlers never write queries. Schema changes are **appended** to `migrations` in `schema.go`; never edit a shipped migration.
- Every client-visible behavior gets a contract test in `internal/api/api_test.go`.
- Invariants that are easy to break: the LWW upsert uses `>=` (not `>`); an empty sync push writes nothing; 401 is only for a bad token (the client signs out on it), and permission errors are 403.
- Deploy target: arm64 Raspberry Pi in Docker. cloudflared runs on the host, and ports are published on 127.0.0.1.
- The admin UI (`internal/admin`) runs on its own listener (`ADMIN_ADDR`). Pages are rendered on the server with html/template and have no JavaScript. The CSP forbids inline styles, so never use `style=` attributes; `<progress>` draws the bars. Flash and error messages come from fixed key→text maps, so they never reflect query text. Admin-issued codes and their read-only stats queries live in `internal/store` and are shared with the CLI.
- To check the UI visually: run the image with `ADMIN_INSECURE_NO_AUTH=true` on a Docker network and screenshot it with `zenika/alpine-chrome --no-sandbox --screenshot` (chromedp/headless-shell hangs on `--screenshot`).
