package api

// Contract tests: each one pins a behavior from docs/selfhost/SERVER_SPEC.md
// that the Submarine client depends on. They drive the real HTTP handler
// against a real SQLite file.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/secret"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

type sentMail struct{ to, subject, body string }

type captureMailer struct {
	sent chan sentMail
}

func (m *captureMailer) Send(to, subject, body string) error {
	m.sent <- sentMail{to, subject, body}
	return nil
}

type env struct {
	t     *testing.T
	api   *Server
	http  *httptest.Server
	store *store.Store
	mail  *captureMailer
}

func newEnv(t *testing.T, mutate ...func(*config.Config)) *env {
	t.Helper()
	cfg := config.Config{
		Signup:       config.SignupOpen,
		MaxBodyBytes: 20 << 20,
		MaxBlobChars: 8 << 20,
		ServerName:   "Test",
	}
	for _, m := range mutate {
		m(&cfg)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mailer := &captureMailer{sent: make(chan sentMail, 16)}
	srv := New(cfg, st, mailer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Tests make many auth calls from one IP; the limiter has its own test.
	srv.ipLimit = newLimiter(1e6, 1e6)
	srv.emailLimit = newLimiter(1e6, 1e6)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &env{t: t, api: srv, http: hs, store: st, mail: mailer}
}

type resp struct {
	status int
	raw    []byte
}

func (r resp) obj() map[string]any {
	var m map[string]any
	json.Unmarshal(r.raw, &m)
	return m
}

func (r resp) records() []store.Record {
	var body struct {
		Records []store.Record `json:"records"`
	}
	json.Unmarshal(r.raw, &body)
	return body.Records
}

func (e *env) call(method, path, token string, body any, headers ...string) resp {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.http.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, raw}
}

func (e *env) post(path, token string, body any) resp { return e.call("POST", path, token, body) }

func (e *env) expect(r resp, status int) resp {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status %d, want %d; body: %s", r.status, status, r.raw)
	}
	return r
}

var codeRE = regexp.MustCompile(`\b[0-9a-f]{32}\b`)

// nextCode waits for the next email to `to` and returns the code in it.
func (e *env) nextCode(to string) string {
	e.t.Helper()
	select {
	case m := <-e.mail.sent:
		if m.to != to {
			e.t.Fatalf("mail went to %s, want %s", m.to, to)
		}
		code := codeRE.FindString(m.body)
		if code == "" {
			e.t.Fatalf("no code in mail body: %s", m.body)
		}
		return code
	case <-time.After(2 * time.Second):
		e.t.Fatalf("no mail sent to %s", to)
	}
	return ""
}

func (e *env) noMail() {
	e.t.Helper()
	select {
	case m := <-e.mail.sent:
		e.t.Fatalf("unexpected mail to %s: %s", m.to, m.subject)
	case <-time.After(100 * time.Millisecond):
	}
}

// newUser creates an account with a password and returns a bearer token.
func (e *env) newUser(email string) string {
	e.t.Helper()
	if _, err := e.store.CreateUser(e.t.Context(), email); err != nil {
		e.t.Fatal(err)
	}
	code := secret.NewToken(16)
	if err := e.store.CreateEmailToken(e.t.Context(), secret.Hash(code), email, store.PurposeReset, time.Hour); err != nil {
		e.t.Fatal(err)
	}
	r := e.expect(e.post("/auth/reset-with-token", "", map[string]string{"reset_token": code, "password": "hunter2222"}), 200)
	return r.obj()["token"].(string)
}

func rec(uuid, stamp, blob string) store.Record {
	return store.Record{UUID: uuid, EntityType: "notes", UpdatedAt: stamp, Blob: &blob}
}

func tomb(uuid, stamp string) store.Record {
	return store.Record{UUID: uuid, EntityType: "notes", UpdatedAt: stamp, Deleted: true}
}

func byUUID(recs []store.Record) map[string]store.Record {
	m := map[string]store.Record{}
	for _, r := range recs {
		m[r.UUID] = r
	}
	return m
}

func blobOf(r store.Record) string {
	if r.Blob == nil {
		return "<nil>"
	}
	return *r.Blob
}

const (
	t1     = "001758899999001:00000:aaaaaaaaaaaaaaaa"
	t2     = "001758899999002:00000:aaaaaaaaaaaaaaaa"
	t3     = "001758899999003:00000:aaaaaaaaaaaaaaaa"
	prof   = "0123456789abcdef0123456789abcdef"
	shareA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func TestSignupFlow(t *testing.T) {
	e := newEnv(t)
	r := e.expect(e.post("/auth/signup", "", map[string]string{"email": "  New@Example.com "}), 200)
	if _, ok := r.obj()["status"].(string); !ok {
		t.Fatalf("signup response needs a string status: %s", r.raw)
	}
	verify := e.nextCode("new@example.com")

	r = e.expect(e.call("GET", "/auth/verify?token="+verify, "", nil), 200)
	claim := r.obj()["claim_token"].(string)
	if r.obj()["email"] != "new@example.com" {
		t.Fatalf("verify email = %v", r.obj()["email"])
	}
	e.expect(e.call("GET", "/auth/verify?token="+verify, "", nil), 400) // single use

	e.expect(e.post("/auth/set-password", "", map[string]string{"claim_token": claim, "password": "short"}), 400)
	r = e.expect(e.post("/auth/set-password", "", map[string]string{"claim_token": claim, "password": "longenough"}), 200)
	tok := r.obj()["token"].(string)
	e.expect(e.call("GET", "/keys/me", tok, nil), 200)
	e.expect(e.post("/auth/set-password", "", map[string]string{"claim_token": claim, "password": "longenough"}), 400)

	// Signing up again sends a notice, not a verify code: sign-up must not
	// double as an unauthenticated password reset.
	e.expect(e.post("/auth/signup", "", map[string]string{"email": "new@example.com"}), 200)
	m := <-e.mail.sent
	if codeRE.MatchString(m.body) {
		t.Fatalf("existing-account signup mail contains a code: %s", m.body)
	}
}

func TestSignupModes(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Signup = config.SignupAllowlist })
	e.expect(e.post("/auth/signup", "", map[string]string{"email": "stranger@example.com"}), 403)
	e.noMail()
	e.store.AllowlistAdd(t.Context(), "friend@example.com")
	e.expect(e.post("/auth/signup", "", map[string]string{"email": "Friend@example.com"}), 200)
	e.nextCode("friend@example.com")

	closed := newEnv(t, func(c *config.Config) { c.Signup = config.SignupClosed })
	closed.store.AllowlistAdd(t.Context(), "friend@example.com")
	closed.expect(closed.post("/auth/signup", "", map[string]string{"email": "friend@example.com"}), 403)
}

func TestLoginLogout(t *testing.T) {
	e := newEnv(t)
	e.newUser("a@example.com")
	r := e.expect(e.post("/auth/login", "", map[string]string{"email": "A@Example.com", "password": "hunter2222"}), 200)
	tok := r.obj()["token"].(string)
	if r.obj()["email"] != "a@example.com" {
		t.Fatalf("login should return the canonical email, got %v", r.obj()["email"])
	}
	e.expect(e.post("/auth/login", "", map[string]string{"email": "a@example.com", "password": "wrongwrong"}), 401)
	e.expect(e.post("/auth/login", "", map[string]string{"email": "nobody@example.com", "password": "wrongwrong"}), 401)

	e.expect(e.post("/auth/logout", tok, nil), 200)
	e.expect(e.call("GET", "/keys/me", tok, nil), 401)
}

func TestLoginBackoffIsPerIP(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TrustProxyHeader = "CF-Connecting-IP" })
	e.newUser("a@example.com")
	login := func(pw, ip string) resp {
		return e.call("POST", "/auth/login", "", map[string]string{"email": "a@example.com", "password": pw},
			"CF-Connecting-IP", ip)
	}
	for i := 0; i < freeAttempts; i++ {
		e.expect(login("wrongwrong", "1.1.1.1"), 401)
	}
	e.expect(login("hunter2222", "1.1.1.1"), 429) // attacker IP is throttled...
	e.expect(login("hunter2222", "2.2.2.2"), 200) // ...but the owner is not locked out
}

func TestResetSignsOutOtherDevices(t *testing.T) {
	e := newEnv(t)
	devA := e.newUser("a@example.com")
	devB := e.expect(e.post("/auth/login", "", map[string]string{"email": "a@example.com", "password": "hunter2222"}), 200).obj()["token"].(string)

	e.expect(e.post("/auth/request-reset", "", map[string]string{"email": "a@example.com"}), 200)
	first := e.nextCode("a@example.com")
	e.expect(e.post("/auth/request-reset", "", map[string]string{"email": "a@example.com"}), 200)
	second := e.nextCode("a@example.com")

	r := e.expect(e.post("/auth/reset-with-token", "", map[string]string{"reset_token": second, "password": "brandnewpw"}), 200)
	fresh := r.obj()["token"].(string)
	e.expect(e.call("GET", "/keys/me", devA, nil), 401)
	e.expect(e.call("GET", "/keys/me", devB, nil), 401)
	e.expect(e.call("GET", "/keys/me", fresh, nil), 200)
	// Other outstanding reset codes are void.
	e.expect(e.post("/auth/reset-with-token", "", map[string]string{"reset_token": first, "password": "anotherpw1"}), 400)
	e.expect(e.post("/auth/login", "", map[string]string{"email": "a@example.com", "password": "brandnewpw"}), 200)
}

func TestRequestEndpointsDontEnumerate(t *testing.T) {
	e := newEnv(t)
	e.newUser("a@example.com")
	for _, path := range []string{"/auth/request-reset", "/auth/request-login"} {
		known := e.expect(e.post(path, "", map[string]string{"email": "a@example.com"}), 200)
		e.nextCode("a@example.com")
		unknown := e.expect(e.post(path, "", map[string]string{"email": "ghost@example.com"}), 200)
		e.noMail()
		if !bytes.Equal(known.raw, unknown.raw) {
			t.Fatalf("%s: responses differ: %s vs %s", path, known.raw, unknown.raw)
		}
	}
}

func TestMagicLink(t *testing.T) {
	e := newEnv(t)
	e.newUser("a@example.com")
	e.expect(e.post("/auth/request-login", "", map[string]string{"email": "a@example.com"}), 200)
	code := e.nextCode("a@example.com")
	r := e.expect(e.post("/auth/login-with-link", "", map[string]string{"login_token": code}), 200)
	e.expect(e.call("GET", "/keys/me", r.obj()["token"].(string), nil), 200)
	e.expect(e.post("/auth/login-with-link", "", map[string]string{"login_token": code}), 400)
}

func TestDisabledUser(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	u, _ := e.store.UserByEmail(t.Context(), "a@example.com")
	e.store.SetDisabled(t.Context(), u.ID, true)
	e.expect(e.call("GET", "/keys/me", tok, nil), 401)
	e.expect(e.post("/auth/login", "", map[string]string{"email": "a@example.com", "password": "hunter2222"}), 401)
	e.expect(e.post("/auth/request-login", "", map[string]string{"email": "a@example.com"}), 200)
	e.noMail()
}

// Spec §10.10: a bogus token is 401 everywhere; the client signs out on 401.
func TestBogusTokenIs401(t *testing.T) {
	e := newEnv(t)
	for _, ep := range []struct{ method, path string }{
		{"POST", "/auth/logout"}, {"POST", "/sync"}, {"GET", "/sync/profiles"}, {"POST", "/sync/delete"},
		{"POST", "/keys/publish"}, {"GET", "/keys/me"}, {"POST", "/keys/lookup"},
		{"POST", "/shares/list"}, {"POST", "/shares/sync"}, {"POST", "/shares/create"},
	} {
		if r := e.call(ep.method, ep.path, "bogus", map[string]any{}); r.status != 401 {
			t.Errorf("%s %s with bogus token: %d, want 401", ep.method, ep.path, r.status)
		}
	}
}

func TestAuthorizationBearerAccepted(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	e.expect(e.call("GET", "/keys/me", "", nil, "Authorization", "Bearer "+tok), 200)
}

// ---------------------------------------------------------------------------
// Personal sync
// ---------------------------------------------------------------------------

func TestSyncLastWriteWins(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	sync := func(recs ...store.Record) []store.Record {
		t.Helper()
		if recs == nil {
			recs = []store.Record{}
		}
		return e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "since": "", "records": recs}), 200).records()
	}

	sync(rec("r1", t2, "b2"))
	got := byUUID(sync(rec("r1", t1, "b1-older")))
	if blobOf(got["r1"]) != "b2" {
		t.Fatalf("older write replaced newer: %s", blobOf(got["r1"]))
	}
	// Equal stamps must replace (key rotation, escrow refresh — spec §5.1).
	got = byUUID(sync(rec("r1", t2, "b2-resealed")))
	if blobOf(got["r1"]) != "b2-resealed" {
		t.Fatalf("equal-stamp push not accepted: %s", blobOf(got["r1"]))
	}
	got = byUUID(sync(tomb("r1", t3)))
	if !got["r1"].Deleted || got["r1"].Blob != nil {
		t.Fatalf("newer tombstone didn't replace live row: %+v", got["r1"])
	}
	got = byUUID(sync(rec("r1", t2, "stale-resurrect")))
	if !got["r1"].Deleted {
		t.Fatal("older live row resurrected a newer tombstone")
	}
	got = byUUID(sync(rec("r1", "001758899999004:00000:aaaaaaaaaaaaaaaa", "revived")))
	if got["r1"].Deleted || blobOf(got["r1"]) != "revived" {
		t.Fatalf("newer live row didn't replace tombstone: %+v", got["r1"])
	}
}

func TestSyncResponseShape(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	r := e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "since": "",
		"records": []store.Record{rec("live", t1, "00ff"), tomb("gone", t1)}}), 200)
	var body struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(r.raw, &body); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, r.raw)
	}
	for _, rec := range body.Records {
		for _, f := range []string{"uuid", "entity_type", "updated_at", "deleted"} {
			if _, ok := rec[f]; !ok {
				t.Errorf("record missing required field %s: %v", f, rec)
			}
		}
		if rec["uuid"] == "gone" {
			if _, ok := rec["blob"]; ok {
				t.Errorf("tombstone should omit blob: %v", rec)
			}
		}
	}
	// An empty partition still returns an (empty) records array.
	r = e.expect(e.post("/sync", tok, map[string]any{"profile": "other", "since": "", "records": []any{}}), 200)
	if !strings.Contains(string(r.raw), `"records":[]`) {
		t.Fatalf("empty partition response: %s", r.raw)
	}
}

func TestSyncSince(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	e.post("/sync", tok, map[string]any{"profile": prof, "records": []store.Record{rec("old", t1, "a"), rec("new", t3, "b")}})
	got := e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "since": t2, "records": []any{}}), 200).records()
	if len(got) != 1 || got[0].UUID != "new" {
		t.Fatalf("since filter returned %+v", got)
	}
}

// Spec §5.1.6: dry runs and restore peeks rely on an empty push writing
// nothing — not even the partition's display name.
func TestEmptyPushIsPureRead(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "since": "", "records": []any{}, "name": "Work"}), 200)
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "since": ""}), 200)
	r := e.expect(e.call("GET", "/sync/profiles", tok, nil), 200)
	if !strings.Contains(string(r.raw), `"profiles":[]`) {
		t.Fatalf("empty push created a partition: %s", r.raw)
	}
}

func TestPartitionsAreIsolated(t *testing.T) {
	e := newEnv(t)
	a := e.newUser("a@example.com")
	b := e.newUser("b@example.com")
	e.post("/sync", a, map[string]any{"profile": prof, "records": []store.Record{rec("secret", t1, "aa")}})
	got := e.expect(e.post("/sync", b, map[string]any{"profile": prof, "records": []any{}}), 200).records()
	if len(got) != 0 {
		t.Fatalf("user b sees user a's records: %+v", got)
	}
}

func TestProfilesAndDelete(t *testing.T) {
	e := newEnv(t)
	tok := e.newUser("a@example.com")
	escrow := store.Record{UUID: "0000000000000000000000000000dead", EntityType: "dek_escrow",
		UpdatedAt: "000000000000000:00000:0", Blob: ptr("sealed")}
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "name": "Work",
		"records": []store.Record{rec("a", t1, "aa"), rec("b", t1, "bb"), tomb("c", t1), escrow}}), 200)
	e.expect(e.post("/sync", tok, map[string]any{"profile": "legacy-name",
		"records": []store.Record{tomb("x", t1)}}), 200)

	// Escrow refresh: same sentinel stamp, new blob, must be accepted.
	escrow.Blob = ptr("resealed")
	got := byUUID(e.expect(e.post("/sync", tok, map[string]any{"profile": prof,
		"records": []store.Record{escrow}}), 200).records())
	if blobOf(got[escrow.UUID]) != "resealed" {
		t.Fatalf("escrow refresh rejected: %s", blobOf(got[escrow.UUID]))
	}

	var body struct {
		Profiles []struct {
			Profile     string `json:"profile"`
			Name        string `json:"name"`
			Records     int    `json:"records"`
			LiveRecords int    `json:"live_records"`
			LastUpdated string `json:"last_updated"`
		} `json:"profiles"`
	}
	json.Unmarshal(e.expect(e.call("GET", "/sync/profiles", tok, nil), 200).raw, &body)
	if len(body.Profiles) != 2 {
		t.Fatalf("want 2 profiles, got %+v", body.Profiles)
	}
	for _, p := range body.Profiles {
		switch p.Profile {
		case prof:
			if p.Name != "Work" || p.Records != 4 || p.LiveRecords != 2 || p.LastUpdated == "" {
				t.Errorf("work profile: %+v", p)
			}
		case "legacy-name":
			if p.Name != "legacy-name" || p.Records != 1 || p.LiveRecords != 0 {
				t.Errorf("legacy profile should fall back to its key as name: %+v", p)
			}
		}
	}

	r := e.expect(e.post("/sync/delete", tok, map[string]string{"profile": prof}), 200)
	if r.obj()["deleted"] != float64(4) {
		t.Fatalf("delete count: %s", r.raw)
	}
	r = e.expect(e.post("/sync/delete", tok, map[string]string{"profile": "never-synced"}), 200)
	if r.obj()["deleted"] != float64(0) {
		t.Fatalf("delete of missing partition: %s", r.raw)
	}
	// A force push after delete repopulates without the old name leaking back.
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "records": []store.Record{rec("a", t1, "aa")}}), 200)
	json.Unmarshal(e.expect(e.call("GET", "/sync/profiles", tok, nil), 200).raw, &body)
	for _, p := range body.Profiles {
		if p.Profile == prof && p.Name != prof {
			t.Errorf("display name survived /sync/delete: %+v", p)
		}
	}
}

func TestRecordValidation(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxBlobChars = 8 })
	tok := e.newUser("a@example.com")
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "records": []store.Record{{EntityType: "notes", UpdatedAt: t1}}}), 400)
	e.expect(e.post("/sync", tok, map[string]any{"profile": prof, "records": []store.Record{rec("big", t1, "0123456789")}}), 413)
	e.expect(e.post("/sync", tok, map[string]any{"profile": "", "records": []any{}}), 400)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func TestKeys(t *testing.T) {
	e := newEnv(t)
	a := e.newUser("a@example.com")
	b := e.newUser("b@example.com")

	r := e.expect(e.call("GET", "/keys/me", a, nil), 200)
	if r.obj()["exists"] != false {
		t.Fatalf("keys/me before publish: %s", r.raw)
	}
	keys := map[string]string{"public_key": "pk1", "wrapped_privkey": "wrapped", "enc_salt": "salt"}
	r = e.expect(e.post("/keys/publish", a, keys), 200)
	if r.obj()["created"] != true || r.obj()["rotated"] != false {
		t.Fatalf("first publish: %s", r.raw)
	}
	r = e.expect(e.post("/keys/publish", a, keys), 200)
	if r.obj()["created"] != false || r.obj()["rotated"] != false {
		t.Fatalf("republish: %s", r.raw)
	}
	keys["public_key"] = "pk2"
	r = e.expect(e.post("/keys/publish", a, keys), 200)
	if r.obj()["created"] != false || r.obj()["rotated"] != true {
		t.Fatalf("rotate: %s", r.raw)
	}
	r = e.expect(e.call("GET", "/keys/me", a, nil), 200)
	if r.obj()["exists"] != true || r.obj()["public_key"] != "pk2" || r.obj()["wrapped_privkey"] != "wrapped" {
		t.Fatalf("keys/me: %s", r.raw)
	}

	r = e.expect(e.post("/keys/lookup", b, map[string]string{"email": " A@EXAMPLE.com"}), 200)
	if r.obj()["email"] != "a@example.com" || r.obj()["public_key"] != "pk2" || r.obj()["user_id"] == nil {
		t.Fatalf("lookup: %s", r.raw)
	}
	noKey := e.post("/keys/lookup", a, map[string]string{"email": "b@example.com"})
	ghost := e.post("/keys/lookup", a, map[string]string{"email": "ghost@example.com"})
	e.expect(noKey, 404)
	e.expect(ghost, 404)
	if !bytes.Equal(noKey.raw, ghost.raw) {
		t.Fatalf("lookup 404s differ (enumeration): %s vs %s", noKey.raw, ghost.raw)
	}
}

// ---------------------------------------------------------------------------
// Shares
// ---------------------------------------------------------------------------

func TestSharingLifecycle(t *testing.T) {
	e := newEnv(t)
	x := e.newUser("x@example.com")
	y := e.newUser("y@example.com")
	z := e.newUser("z@example.com")
	ids := map[string]float64{}
	for _, email := range []string{"y@example.com", "z@example.com"} {
		u, _ := e.store.UserByEmail(t.Context(), email)
		ids[email] = float64(u.ID)
	}
	shareSync := func(tok string, recs ...store.Record) resp {
		if recs == nil {
			recs = []store.Record{}
		}
		return e.post("/shares/sync", tok, map[string]any{"share_id": shareA, "since": "", "records": recs})
	}

	e.expect(e.post("/shares/create", x, map[string]string{"share_id": shareA, "name": "Team", "sealed_dek": "dek-x1"}), 200)
	e.expect(e.post("/shares/create", y, map[string]string{"share_id": shareA, "name": "Hijack", "sealed_dek": "evil"}), 403)

	r := e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "Y@example.com", "role": "editor", "sealed_dek": "dek-y1"}), 200)
	if r.obj()["member_user_id"] != ids["y@example.com"] {
		t.Fatalf("invite: %s", r.raw)
	}
	e.expect(e.post("/shares/invite", y, map[string]string{"share_id": shareA, "email": "z@example.com", "role": "editor", "sealed_dek": "d"}), 403)
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "x@example.com", "role": "editor", "sealed_dek": "d"}), 400)
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "z@example.com", "role": "owner", "sealed_dek": "d"}), 400)
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "ghost@example.com", "role": "user", "sealed_dek": "d"}), 404)

	// Y sees a pending invite (and X sees the share as owner).
	var list struct {
		Shares []map[string]string `json:"shares"`
	}
	json.Unmarshal(e.expect(e.post("/shares/list", y, map[string]any{}), 200).raw, &list)
	if len(list.Shares) != 1 || list.Shares[0]["status"] != "pending" || list.Shares[0]["owner_email"] != "x@example.com" || list.Shares[0]["role"] != "editor" {
		t.Fatalf("y's share list: %+v", list.Shares)
	}
	json.Unmarshal(e.expect(e.post("/shares/list", x, map[string]any{}), 200).raw, &list)
	if len(list.Shares) != 1 || list.Shares[0]["role"] != "owner" || list.Shares[0]["status"] != "active" {
		t.Fatalf("x's share list: %+v", list.Shares)
	}

	e.expect(shareSync(y), 403) // not accepted yet
	r = e.expect(e.post("/shares/dek", y, map[string]string{"share_id": shareA}), 200)
	if r.obj()["sealed_dek"] != "dek-y1" || r.obj()["status"] != "pending" {
		t.Fatalf("pending dek: %s", r.raw)
	}
	r = e.expect(e.post("/shares/accept", y, map[string]string{"share_id": shareA}), 200)
	if r.obj()["role"] != "editor" || r.obj()["sealed_dek"] != "dek-y1" {
		t.Fatalf("accept: %s", r.raw)
	}
	e.expect(e.post("/shares/accept", y, map[string]string{"share_id": shareA}), 200) // idempotent
	e.expect(e.post("/shares/accept", z, map[string]string{"share_id": shareA}), 404)

	// Edits flow both ways.
	e.expect(shareSync(x, rec("s1", t1, "from-x")), 200)
	got := byUUID(e.expect(shareSync(y, rec("s2", t1, "from-y")), 200).records())
	if blobOf(got["s1"]) != "from-x" || blobOf(got["s2"]) != "from-y" {
		t.Fatalf("editor sync: %+v", got)
	}

	// Downgrade Y to viewer: pulls work, pushes are 403 read_only (never 401).
	e.expect(e.post("/shares/set-role", x, map[string]any{"share_id": shareA, "member_user_id": ids["y@example.com"], "role": "user"}), 200)
	e.expect(shareSync(y), 200)
	r = e.expect(shareSync(y, rec("s3", t2, "nope")), 403)
	if r.obj()["error"] != "read_only" {
		t.Fatalf("viewer push error: %s", r.raw)
	}
	e.expect(e.post("/shares/set-role", x, map[string]any{"share_id": shareA, "member_user_id": ids["z@example.com"], "role": "user"}), 404)

	// Add Z, then revoke Y and rotate the key the way the client does.
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "z@example.com", "role": "editor", "sealed_dek": "dek-z1"}), 200)
	e.expect(e.post("/shares/accept", z, map[string]string{"share_id": shareA}), 200)
	e.expect(e.post("/shares/revoke", x, map[string]any{"share_id": shareA, "member_user_id": ids["y@example.com"]}), 200)
	e.expect(shareSync(y), 403)
	e.expect(e.post("/shares/dek", y, map[string]string{"share_id": shareA}), 404)

	e.expect(e.post("/shares/create", x, map[string]string{"share_id": shareA, "name": "Team", "sealed_dek": "dek-x2"}), 200)
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "z@example.com", "role": "editor", "sealed_dek": "dek-z2"}), 200)
	r = e.expect(e.post("/shares/dek", z, map[string]string{"share_id": shareA}), 200)
	if r.obj()["sealed_dek"] != "dek-z2" || r.obj()["status"] != "active" {
		t.Fatalf("re-invite must keep status and replace the DEK: %s", r.raw)
	}
	got = byUUID(e.expect(shareSync(x, rec("s1", t1, "from-x-resealed"), rec("s2", t1, "from-y-resealed")), 200).records())
	if blobOf(got["s1"]) != "from-x-resealed" || blobOf(got["s2"]) != "from-y-resealed" {
		t.Fatalf("equal-stamp re-push after rotation not accepted: %+v", got)
	}

	var members struct {
		Members []map[string]any `json:"members"`
	}
	json.Unmarshal(e.expect(e.post("/shares/members", z, map[string]string{"share_id": shareA}), 200).raw, &members)
	if len(members.Members) != 2 || members.Members[0]["role"] != "owner" {
		t.Fatalf("roster after revoke: %+v", members.Members)
	}

	// Re-inviting a revoked member starts fresh as pending.
	e.expect(e.post("/shares/invite", x, map[string]string{"share_id": shareA, "email": "y@example.com", "role": "user", "sealed_dek": "dek-y2"}), 200)
	r = e.expect(e.post("/shares/dek", y, map[string]string{"share_id": shareA}), 200)
	if r.obj()["status"] != "pending" {
		t.Fatalf("re-invite after revoke: %s", r.raw)
	}

	// Leave / owner restrictions.
	e.expect(e.post("/shares/leave", x, map[string]string{"share_id": shareA}), 400)
	e.expect(e.post("/shares/revoke", x, map[string]any{"share_id": shareA, "member_user_id": 1}), 400)
	e.expect(e.post("/shares/leave", z, map[string]string{"share_id": shareA}), 200)
	e.expect(e.post("/shares/leave", z, map[string]string{"share_id": shareA}), 404)

	// Delete cascades.
	e.expect(e.post("/shares/delete", y, map[string]string{"share_id": shareA}), 403)
	e.expect(e.post("/shares/delete", x, map[string]string{"share_id": shareA}), 200)
	json.Unmarshal(e.expect(e.post("/shares/list", y, map[string]any{}), 200).raw, &list)
	if len(list.Shares) != 0 {
		t.Fatalf("share survived delete: %+v", list.Shares)
	}
	e.expect(shareSync(x), 403)
}

func TestOkEndpointsReturnJSON(t *testing.T) {
	e := newEnv(t)
	x := e.newUser("x@example.com")
	r := e.expect(e.post("/shares/create", x, map[string]string{"share_id": shareA, "name": "T", "sealed_dek": "d"}), 200)
	if r.obj()["ok"] != true {
		t.Fatalf("expected {\"ok\":true}, got %s", r.raw)
	}
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

func TestBasePath(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.BasePath = "/submarine" })
	e.expect(e.call("GET", "/submarine/health", "", nil), 200)
	e.expect(e.post("/submarine/auth/signup", "", map[string]string{"email": "a@example.com"}), 200)
	e.expect(e.call("GET", "/health", "", nil), 404)
}

func TestIPRateLimit(t *testing.T) {
	e := newEnv(t)
	e.api.ipLimit = newLimiter(0.001, 3)
	for i := 0; i < 3; i++ {
		e.expect(e.post("/auth/login", "", map[string]string{"email": "a@b.c", "password": "x"}), 401)
	}
	e.expect(e.post("/auth/login", "", map[string]string{"email": "a@b.c", "password": "x"}), 429)
}

func TestUnknownRouteIsJSON404(t *testing.T) {
	e := newEnv(t)
	r := e.expect(e.call("GET", "/nope", "", nil), 404)
	if r.obj()["error"] != "not_found" {
		t.Fatalf("404 body: %s", r.raw)
	}
}

func ptr(s string) *string { return &s }
