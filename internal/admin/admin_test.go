package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/secret"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

const testPassword = "correct horse"

type env struct {
	t     *testing.T
	admin *Server
	http  *httptest.Server
	store *store.Store
}

func newEnv(t *testing.T, mutate ...func(*config.Config)) *env {
	t.Helper()
	cfg := config.Config{Signup: config.SignupAllowlist, AdminPassword: testPassword}
	for _, m := range mutate {
		m(&cfg)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	hs := httptest.NewServer(a.Handler())
	t.Cleanup(hs.Close)
	return &env{t: t, admin: a, http: hs, store: st}
}

type resp struct {
	status   int
	body     string
	location string
}

// do sends a same-origin request with the admin password unless the caller
// overrides headers ("-auth" drops basic auth).
func (e *env) do(method, path string, form url.Values, headers ...string) resp {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.http.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.SetBasicAuth("admin", testPassword)
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "-auth" {
			req.Header.Del("Authorization")
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, string(b), res.Header.Get("Location")}
}

func (e *env) get(path string) resp { return e.do("GET", path, nil) }

func (e *env) post(path string, kv ...string) resp {
	form := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		form.Set(kv[i], kv[i+1])
	}
	return e.do("POST", path, form)
}

func (e *env) expect(r resp, status int, contains ...string) resp {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status %d, want %d; body:\n%s", r.status, status, r.body)
	}
	for _, s := range contains {
		if !strings.Contains(r.body, s) {
			e.t.Fatalf("body lacks %q:\n%s", s, r.body)
		}
	}
	return r
}

func (e *env) userID(email string) int64 {
	e.t.Helper()
	u, err := e.store.UserByEmail(e.t.Context(), email)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.ID
}

func itoa(n int64) string { return big.NewInt(n).String() }

var codeRE = regexp.MustCompile(`<code class="code">([0-9a-f]{32})</code>`)

// ---------------------------------------------------------------------------

func TestPasswordRequired(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/", nil, "-auth", "")
	if r.status != 401 {
		t.Fatalf("no credentials: %d", r.status)
	}
	req, _ := http.NewRequest("GET", e.http.URL+"/", nil)
	req.SetBasicAuth("admin", "wrong")
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("wrong password: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	e.expect(e.get("/"), 200, "Users")
}

func TestPasswordGateThrottles(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", e.http.URL+"/", nil)
		req.SetBasicAuth("admin", "guess")
		res, _ := http.DefaultClient.Do(req)
		res.Body.Close()
	}
	if r := e.get("/"); r.status != 429 {
		t.Fatalf("after 10 failures even the right password should wait, got %d", r.status)
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := newEnv(t)
	e.store.CreateUser(t.Context(), "a@example.com")
	id := e.userID("a@example.com")
	r := e.do("POST", "/users/"+itoa(id)+"/disable", url.Values{}, "Sec-Fetch-Site", "cross-site")
	if r.status != 403 {
		t.Fatalf("cross-site POST: %d", r.status)
	}
	if u, _ := e.store.UserByEmail(t.Context(), "a@example.com"); u.Disabled {
		t.Fatal("cross-site POST disabled the user")
	}
}

func TestCreateUserShowsWorkingCode(t *testing.T) {
	e := newEnv(t)
	r := e.expect(e.post("/users", "email", " New@Example.com "), 200, "Account created", "new@example.com", "Forgot password")
	m := codeRE.FindStringSubmatch(r.body)
	if m == nil {
		t.Fatalf("no code on page:\n%s", r.body)
	}
	if _, err := e.store.ResetPassword(t.Context(), secret.Hash(m[1]), secret.HashPassword("hunter2222"), secret.Hash("bearer")); err != nil {
		t.Fatalf("code from the admin UI doesn't work as a reset token: %v", err)
	}

	r = e.expect(e.post("/users", "email", "new@example.com"), 303)
	if !strings.Contains(r.location, "err=exists") {
		t.Fatalf("duplicate create redirect: %s", r.location)
	}
	e.expect(e.get(r.location), 200, "already exists")
	r = e.expect(e.post("/users", "email", "not an email"), 303)
	if !strings.Contains(r.location, "err=email") {
		t.Fatalf("invalid email redirect: %s", r.location)
	}
}

// seed creates users, synced data and a share so every page has content.
func (e *env) seed() (alice, bob int64) {
	ctx := e.t.Context()
	e.store.CreateUser(ctx, "alice@example.com")
	e.store.CreateUser(ctx, "bob@example.com")
	alice, bob = e.userID("alice@example.com"), e.userID("bob@example.com")
	blob := strings.Repeat("ab", 3000) // 3000 bytes decoded
	e.store.MergePersonal(ctx, alice, "0123456789abcdef0123456789abcdef", "Work <b>", []store.Record{
		{UUID: "r1", EntityType: "servers", UpdatedAt: "1", Blob: &blob},
		{UUID: "r2", EntityType: "notes", UpdatedAt: "1", Deleted: true},
	})
	e.store.CreateAuthToken(ctx, alice, secret.Hash("device"))
	e.store.UpsertShare(ctx, "ssssssssssssssssssssssssssssssss", alice, "Team", "dek")
	e.store.UpsertMember(ctx, "ssssssssssssssssssssssssssssssss", bob, store.RoleUser, "dek-b")
	e.store.MergeShared(ctx, "ssssssssssssssssssssssssssssssss", alice, []store.Record{{UUID: "s1", EntityType: "servers", UpdatedAt: "1", Blob: &blob}})
	return alice, bob
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.seed()
	e.store.AllowlistAdd(t.Context(), "friend@example.com")

	e.expect(e.get("/"), 200, "alice@example.com", "bob@example.com", "5.9 KiB", "no password", "Devices")
	e.expect(e.get("/users/"+itoa(alice)), 200,
		"Work &lt;b&gt;", // user-controlled names are escaped
		"2.9 KiB", "Team", "owner", "Signed-in devices", "Delete this user")
	e.expect(e.get("/users/"+itoa(bob)), 200, "Team", "viewer", "pending", "alice@example.com")
	e.expect(e.get("/shares"), 200, "Team", "alice@example.com", "1 pending")
	e.expect(e.get("/shares/ssssssssssssssssssssssssssssssss"), 200, "bob@example.com", "viewer", "Delete this share")
	e.expect(e.get("/signup"), 200, "allowlist", "friend@example.com")
	e.expect(e.get("/static/admin.css"), 200, "--accent")

	e.expect(e.get("/users/9999"), 404, "No such user")
	e.expect(e.get("/users/abc"), 404)
	e.expect(e.get("/shares/nope"), 404)
	e.expect(e.get("/nowhere"), 404)
	// Query-string flash keys never reflect arbitrary text.
	r := e.expect(e.get("/?done=<script>alert(1)</script>"), 200)
	if strings.Contains(r.body, "<script>") {
		t.Fatal("flash reflected query text")
	}
}

func TestUserActions(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.seed()
	base := "/users/" + itoa(alice)
	ctx := t.Context()

	e.expect(e.post(base+"/login-code"), 200, "Sign-in code", "Sign in by email")
	e.expect(e.post(base+"/reset-code"), 200, "Password reset code")

	r := e.expect(e.post(base+"/signout"), 303)
	e.expect(e.get(r.location), 200, "Signed out every device")
	if s, _ := e.store.Sessions(ctx, alice); len(s) != 0 {
		t.Fatalf("sessions after sign-out: %v", s)
	}

	e.expect(e.post(base+"/disable"), 303)
	if u, _ := e.store.UserByID(ctx, alice); !u.Disabled {
		t.Fatal("disable didn't")
	}
	e.expect(e.get(base), 200, "disabled", "Enable account")
	e.expect(e.post(base+"/enable"), 303)
	if u, _ := e.store.UserByID(ctx, alice); u.Disabled {
		t.Fatal("enable didn't")
	}

	r = e.expect(e.post(base+"/delete", "confirm", "someone-else@example.com"), 303)
	if !strings.Contains(r.location, "err=confirm") {
		t.Fatalf("mismatched confirm: %s", r.location)
	}
	if _, err := e.store.UserByID(ctx, alice); err != nil {
		t.Fatal("user deleted despite mismatched confirmation")
	}
	r = e.expect(e.post(base+"/delete", "confirm", "Alice@Example.com"), 303)
	if r.location != "/?done=deleted" {
		t.Fatalf("delete redirect: %s", r.location)
	}
	if _, err := e.store.UserByID(ctx, alice); err == nil {
		t.Fatal("user survived delete")
	}
	if sh, _ := e.store.ShareStats(ctx); len(sh) != 0 {
		t.Fatal("owned share survived user delete")
	}
	e.expect(e.post(base+"/nonsense"), 404)
}

func TestDeleteShare(t *testing.T) {
	e := newEnv(t)
	e.seed()
	path := "/shares/ssssssssssssssssssssssssssssssss"
	r := e.expect(e.post(path+"/delete", "confirm", "team"), 303) // case matters for share names
	if !strings.Contains(r.location, "err=confirm") {
		t.Fatalf("mismatched confirm: %s", r.location)
	}
	e.expect(e.post(path+"/delete", "confirm", "Team"), 303)
	if sh, _ := e.store.ShareStats(t.Context()); len(sh) != 0 {
		t.Fatal("share survived delete")
	}
}

func TestAllowlist(t *testing.T) {
	e := newEnv(t)
	r := e.expect(e.post("/signup/allow", "email", "Friend@Example.com"), 303)
	e.expect(e.get(r.location), 200, "friend@example.com", "Added to the sign-up allowlist")
	e.expect(e.post("/signup/remove", "email", "friend@example.com"), 303)
	if ok, _ := e.store.IsAllowlisted(t.Context(), "friend@example.com"); ok {
		t.Fatal("remove didn't")
	}
	r = e.expect(e.post("/signup/remove", "email", "friend@example.com"), 303)
	if !strings.Contains(r.location, "err=notfound") {
		t.Fatalf("removing a missing entry: %s", r.location)
	}
}

// ---------------------------------------------------------------------------
// Cloudflare Access
// ---------------------------------------------------------------------------

type fakeAccess struct {
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
	hits   int
}

func newFakeAccess(t *testing.T) *fakeAccess {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAccess{key: key, kid: "kid-1"}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		f.hits++
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": f.kid, "kty": "RSA", "alg": "RS256",
			"n": b64url.EncodeToString(key.N.Bytes()),
			"e": b64url.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAccess) verifier() *accessVerifier {
	return &accessVerifier{issuer: f.server.URL, audience: "app-aud", client: f.server.Client(), now: time.Now}
}

func (f *fakeAccess) token(t *testing.T, claims map[string]any, kid string, signer *rsa.PrivateKey) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signing := b64url.EncodeToString(hdr) + "." + b64url.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64url.EncodeToString(sig)
}

func (f *fakeAccess) claims() map[string]any {
	return map[string]any{
		"iss": f.server.URL, "aud": []string{"app-aud"}, "email": "admin@example.com",
		"exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(),
	}
}

func TestAccessVerifier(t *testing.T) {
	f := newFakeAccess(t)
	v := f.verifier()
	ctx := t.Context()

	email, err := v.verify(ctx, f.token(t, f.claims(), f.kid, f.key))
	if err != nil || email != "admin@example.com" {
		t.Fatalf("valid token: %q %v", email, err)
	}
	c := f.claims()
	c["aud"] = "app-aud" // a bare string aud is also valid
	if _, err := v.verify(ctx, f.token(t, c, f.kid, f.key)); err != nil {
		t.Fatalf("string aud: %v", err)
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := map[string]func() string{
		"empty":      func() string { return "" },
		"garbage":    func() string { return "a.b" },
		"forged sig": func() string { return f.token(t, f.claims(), f.kid, other) },
		"wrong aud":  func() string { c := f.claims(); c["aud"] = []string{"other-app"}; return f.token(t, c, f.kid, f.key) },
		"wrong issuer": func() string {
			c := f.claims()
			c["iss"] = "https://evil.cloudflareaccess.com"
			return f.token(t, c, f.kid, f.key)
		},
		"expired": func() string {
			c := f.claims()
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return f.token(t, c, f.kid, f.key)
		},
		"not yet": func() string {
			c := f.claims()
			c["nbf"] = time.Now().Add(time.Hour).Unix()
			return f.token(t, c, f.kid, f.key)
		},
		"unknown kid": func() string { return f.token(t, f.claims(), "kid-2", f.key) },
	}
	for name, tok := range bad {
		if _, err := v.verify(ctx, tok()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Keys are cached; an unknown kid doesn't hammer Cloudflare.
	if f.hits != 1 {
		t.Errorf("fetched certs %d times, want 1", f.hits)
	}
}

func TestAccessGuardsHandler(t *testing.T) {
	f := newFakeAccess(t)
	e := newEnv(t, func(c *config.Config) { c.AdminPassword = "" })
	e.admin.access = f.verifier()

	r := e.do("GET", "/", nil, "-auth", "")
	if r.status != 403 {
		t.Fatalf("no Access token: %d", r.status)
	}
	tok := f.token(t, f.claims(), f.kid, f.key)
	e.expect(e.do("GET", "/", nil, "-auth", "", "Cf-Access-Jwt-Assertion", tok), 200, "Signed in as admin@example.com")
	e.expect(e.do("GET", "/", nil, "-auth", "", "Cookie", "CF_Authorization="+tok), 200, "admin@example.com")
}
