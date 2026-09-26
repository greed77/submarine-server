// Package api implements the Submarine sync wire protocol described in
// docs/selfhost/SERVER_SPEC.md.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/mail"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/secret"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

type Server struct {
	cfg   config.Config
	store *store.Store
	mail  mail.Mailer
	log   *slog.Logger

	ipLimit     *limiter // unauthenticated /auth/* requests per client IP
	emailLimit  *limiter // outgoing auth emails per address
	lookupLimit *limiter // /keys/lookup per user
	logins      *backoff // failed password logins per (email, IP)
}

func New(cfg config.Config, st *store.Store, mailer mail.Mailer, log *slog.Logger) *Server {
	return &Server{
		cfg:         cfg,
		store:       st,
		mail:        mailer,
		log:         log,
		ipLimit:     newLimiter(30.0/60, 20),
		emailLimit:  newLimiter(1.0/300, 3),
		lookupLimit: newLimiter(1, 30),
		logins:      newBackoff(),
	}
}

type authedHandler func(w http.ResponseWriter, r *http.Request, u *store.User)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	pub := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.limitIP(h)) }
	auth := func(pattern string, h authedHandler) { mux.Handle(pattern, s.requireAuth(h)) }

	mux.HandleFunc("GET /health", s.health)

	pub("POST /auth/signup", s.signup)
	pub("GET /auth/verify", s.verify)
	pub("POST /auth/set-password", s.setPassword)
	pub("POST /auth/login", s.login)
	pub("POST /auth/request-reset", s.requestReset)
	pub("POST /auth/reset-with-token", s.resetWithToken)
	pub("POST /auth/request-login", s.requestLogin)
	pub("POST /auth/login-with-link", s.loginWithLink)
	auth("POST /auth/logout", s.logout)

	auth("POST /sync", s.sync)
	auth("GET /sync/profiles", s.syncProfiles)
	auth("POST /sync/delete", s.syncDelete)

	auth("POST /keys/publish", s.keysPublish)
	auth("GET /keys/me", s.keysMe)
	auth("POST /keys/lookup", s.keysLookup)

	auth("POST /shares/create", s.sharesCreate)
	auth("POST /shares/invite", s.sharesInvite)
	auth("POST /shares/list", s.sharesList)
	auth("POST /shares/dek", s.sharesDEK)
	auth("POST /shares/members", s.sharesMembers)
	auth("POST /shares/accept", s.sharesAccept)
	auth("POST /shares/set-role", s.sharesSetRole)
	auth("POST /shares/revoke", s.sharesRevoke)
	auth("POST /shares/leave", s.sharesLeave)
	auth("POST /shares/delete", s.sharesDelete)
	auth("POST /shares/sync", s.sharesSync)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "No such endpoint")
	})

	var h http.Handler = mux
	if s.cfg.BasePath != "" {
		h = http.StripPrefix(s.cfg.BasePath, h)
	}
	return s.recoverer(s.logRequests(s.limitBody(h)))
}

// RunJanitor periodically purges expired email tokens and idle limiter
// state until ctx is cancelled.
func (s *Server) RunJanitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.store.PurgeEmailTokens(ctx); err != nil {
				s.log.Error("purge email tokens", "err", err)
			} else if n > 0 {
				s.log.Info("purged expired email tokens", "count", n)
			}
			for _, l := range []*limiter{s.ipLimit, s.emailLimit, s.lookupLimit} {
				l.prune(time.Hour)
			}
			s.logins.prune(24 * time.Hour)
		}
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "db_unavailable", "Database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// requireAuth resolves X-Auth-Token (or Authorization: Bearer). 401 is
// reserved for a missing or invalid token, because the client signs the user
// out on any 401.
func (s *Server) requireAuth(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Missing auth token")
			return
		}
		u, err := s.store.UserByToken(r.Context(), secret.Hash(tok))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or expired session")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r, u)
	})
}

func bearerToken(r *http.Request) string {
	if tok := strings.TrimSpace(r.Header.Get("X-Auth-Token")); tok != "" {
		return tok
	}
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (s *Server) limitIP(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ipLimit.allow(s.clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests; try again shortly")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		h.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
	})
}

func (s *Server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal", "Internal server error")
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeader != "" {
		if v := r.Header.Get(s.cfg.TrustProxyHeader); v != "" {
			// X-Forwarded-For style lists: the first entry is the client.
			first, _, _ := strings.Cut(v, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

var okBody = map[string]bool{"ok": true}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "Internal server error")
}

// decode reads a JSON body into v, writing a 400/413 and returning false on
// failure. Unknown fields are ignored so newer clients keep working.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "Request body too large")
	} else {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
	}
	return false
}

// NormalizeEmail trims and lowercases an email and applies a loose sanity
// check. The empty string means invalid.
func NormalizeEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 3 || len(s) > 254 {
		return ""
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return ""
	}
	for _, c := range s {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return ""
		}
	}
	return s
}

// validLen reports whether s is between min and max bytes long.
func validLen(s string, min, max int) bool { return len(s) >= min && len(s) <= max }
