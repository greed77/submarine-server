package admin

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type ctxKey struct{}

// actor returns who is making the request, for display and audit logs.
func actor(r *http.Request) string {
	if a, ok := r.Context().Value(ctxKey{}).(string); ok {
		return a
	}
	return "admin"
}

// authenticate enforces every configured method: Cloudflare Access (the
// JWT is verified here too, so reaching the port directly doesn't bypass
// Access) and/or a password via HTTP basic auth.
func (a *Server) authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := ""
		if a.access != nil {
			tok := r.Header.Get("Cf-Access-Jwt-Assertion")
			if tok == "" {
				if c, err := r.Cookie("CF_Authorization"); err == nil {
					tok = c.Value
				}
			}
			email, err := a.access.verify(r.Context(), tok)
			if err != nil {
				a.log.Warn("admin: Cloudflare Access check failed", "err", err, "remote", r.RemoteAddr)
				http.Error(w, "Forbidden: sign in through Cloudflare Access.", http.StatusForbidden)
				return
			}
			who = email
		}
		if a.cfg.AdminPassword != "" {
			if !a.passwordGate.allow() {
				http.Error(w, "Too many failed sign-in attempts; wait a minute.", http.StatusTooManyRequests)
				return
			}
			_, pw, ok := r.BasicAuth()
			want := sha256.Sum256([]byte(a.cfg.AdminPassword))
			got := sha256.Sum256([]byte(pw))
			if !ok || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
				if ok {
					a.passwordGate.fail()
				}
				w.Header().Set("WWW-Authenticate", `Basic realm="Submarine admin", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if who == "" {
				who = "admin"
			}
		}
		if who == "" {
			who = "admin (unauthenticated)"
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, who)))
	})
}

// failGate blocks password checks for a minute after too many failures. The
// admin password is a single shared secret, so one global gate is enough.
type failGate struct {
	mu     sync.Mutex
	fails  []time.Time
	now    func() time.Time
	limit  int
	window time.Duration
}

func newFailGate() *failGate {
	return &failGate{now: time.Now, limit: 10, window: time.Minute}
}

func (g *failGate) recent() []time.Time {
	cutoff := g.now().Add(-g.window)
	g.fails = slices.DeleteFunc(g.fails, func(t time.Time) bool { return t.Before(cutoff) })
	return g.fails
}

func (g *failGate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.recent()) < g.limit
}

func (g *failGate) fail() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fails = append(g.recent(), g.now())
}

// ---------------------------------------------------------------------------
// Cloudflare Access JWT verification
// ---------------------------------------------------------------------------

type accessVerifier struct {
	issuer   string // https://<team>.cloudflareaccess.com
	audience string // the Access application's AUD tag
	client   *http.Client
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newAccessVerifier(teamDomain, aud string) *accessVerifier {
	return &accessVerifier{
		issuer:   "https://" + teamDomain,
		audience: aud,
		client:   &http.Client{Timeout: 10 * time.Second},
		now:      time.Now,
	}
}

var b64url = base64.RawURLEncoding

// verify checks an Access JWT's signature, issuer, audience and lifetime and
// returns the signed-in identity (email, or the service token name).
func (v *accessVerifier) verify(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("no Access token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return "", fmt.Errorf("unexpected alg %q", hdr.Alg)
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return "", err
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return "", errors.New("bad signature")
	}

	var c struct {
		Iss        string   `json:"iss"`
		Aud        audience `json:"aud"`
		Exp        int64    `json:"exp"`
		Nbf        int64    `json:"nbf"`
		Email      string   `json:"email"`
		CommonName string   `json:"common_name"` // service tokens
		Sub        string   `json:"sub"`
	}
	if err := decodeSegment(parts[1], &c); err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	now := v.now().Unix()
	const skew = 60
	switch {
	case c.Iss != v.issuer:
		return "", fmt.Errorf("issuer %q, want %q", c.Iss, v.issuer)
	case !slices.Contains(c.Aud, v.audience):
		return "", errors.New("token is for a different Access application")
	case c.Exp == 0 || now > c.Exp+skew:
		return "", errors.New("token expired")
	case c.Nbf != 0 && now < c.Nbf-skew:
		return "", errors.New("token not yet valid")
	}
	for _, id := range []string{c.Email, c.CommonName, c.Sub} {
		if id != "" {
			return id, nil
		}
	}
	return "", errors.New("token has no identity")
}

// key returns the signing key for kid, refetching Cloudflare's published
// keys (at most once a minute) when it's unknown, e.g. after a rotation.
func (v *accessVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if v.now().Sub(v.fetchedAt) < time.Minute {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	v.fetchedAt = v.now()
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch Access certs: %w", err)
	}
	v.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *accessVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", v.issuer+"/cdn-cgi/access/certs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := b64url.DecodeString(k.N)
		e, err2 := b64url.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("no RSA keys published")
	}
	return keys, nil
}

func decodeSegment(seg string, v any) error {
	b, err := b64url.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// audience accepts the JWT "aud" claim as a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}
