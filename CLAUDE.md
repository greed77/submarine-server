# submarine-server

Go + SQLite reimplementation of the Submarine sync API. `docs/selfhost/SERVER_SPEC.md` is the contract; the client source (`D:\code\Submarine`, `src-tauri/src/cloud.rs`) is the tiebreaker.

- Go is **not installed** on the dev box. Run the toolchain in Docker (from Git Bash, set `MSYS_NO_PATHCONV=1`, otherwise container paths like `/src` get rewritten):
  `docker run --rm -v "D:/code/submarine-server:/src" -v submarine-gomod:/go/pkg/mod -v submarine-gocache:/root/.cache/go-build -w /src golang:1-alpine go test ./...`
  Use the `golang:1` (Debian) image for `go test -race`, since alpine has no cgo.
- All SQL lives in `internal/store`. Handlers never write queries. Schema changes are **appended** to `migrations` in `schema.go`; never edit a shipped migration.
- Every client-visible behavior gets a contract test in `internal/api/api_test.go`.
- Invariants that are easy to break: the LWW upsert uses `>=` (not `>`); an empty sync push writes nothing; 401 is only for a bad token (the client signs out on it), and permission errors are 403.
- Deploy target: arm64 Raspberry Pi in Docker behind a Cloudflare Tunnel. The planned admin web UI goes on a separate listener.
