package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/config"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/secret"
	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

const (
	verifyTTL = 24 * time.Hour
	claimTTL  = time.Hour
	resetTTL  = time.Hour
	loginTTL  = 15 * time.Minute

	minPasswordLen = 8
	maxPasswordLen = 1024
)

type authTokenResp struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// POST /auth/signup
func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	email := NormalizeEmail(req.Email)
	if email == "" {
		writeError(w, http.StatusBadRequest, "invalid_email", "Enter a valid email address")
		return
	}
	allowed, err := s.signupAllowed(r, email)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "signup_closed", "Sign-up is not open on this server. Ask the administrator for an account.")
		return
	}

	// Same response whether or not the account exists (anti-enumeration).
	sent := func() {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "verification_sent",
			"message": "Check your email for a verification code.",
		})
	}
	if !s.emailLimit.allow(email) {
		sent()
		return
	}
	u, err := s.store.UserByEmail(r.Context(), email)
	switch {
	case err == nil && u.PasswordHash != "":
		s.sendMail(email, "You already have an account",
			fmt.Sprintf("Someone tried to sign up to %s with this email, but it already has an account.\n\n"+
				"If that was you, sign in instead, or use \"Forgot password\" to reset it.\n"+
				"If it wasn't you, you can ignore this message.\n", s.cfg.ServerName))
		sent()
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.internalError(w, r, err)
		return
	}
	tok, err := s.store.NewEmailCode(r.Context(), email, store.PurposeVerify, verifyTTL)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.sendMail(email, "Your verification code", tokenEmail(s.cfg.ServerName,
		"Finish creating your account by pasting this verification code into the app:", tok, verifyTTL))
	sent()
}

func (s *Server) signupAllowed(r *http.Request, email string) (bool, error) {
	switch s.cfg.Signup {
	case config.SignupOpen:
		return true, nil
	case config.SignupAllowlist:
		return s.store.IsAllowlisted(r.Context(), email)
	default:
		return false, nil
	}
}

// GET /auth/verify?token=
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.URL.Query().Get("token"))
	if tok == "" {
		writeError(w, http.StatusBadRequest, "invalid_token", "Missing verification code")
		return
	}
	claim := secret.NewToken(16)
	email, err := s.store.ExchangeVerifyToken(r.Context(), secret.Hash(tok), secret.Hash(claim), claimTTL)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "invalid_token", "That verification code is invalid, expired or already used")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"claim_token": claim, "email": email})
}

// POST /auth/set-password
func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClaimToken string `json:"claim_token"`
		Password   string `json:"password"`
	}
	if !decode(w, r, &req) || !checkPassword(w, req.Password) {
		return
	}
	bearer := secret.NewToken(32)
	email, err := s.store.ClaimAccount(r.Context(), secret.Hash(strings.TrimSpace(req.ClaimToken)),
		secret.HashPassword(req.Password), secret.Hash(bearer))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusBadRequest, "invalid_token", "That sign-up session is invalid or expired; start again")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "account_exists", "This account already exists; sign in or reset your password")
	case err != nil:
		s.internalError(w, r, err)
	default:
		writeJSON(w, http.StatusOK, authTokenResp{Token: bearer, Email: email})
	}
}

// POST /auth/login
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	email := NormalizeEmail(req.Email)
	ip := s.clientIP(r)
	if wait := s.logins.wait(email, ip); wait > 0 {
		writeError(w, http.StatusTooManyRequests, "too_many_attempts",
			fmt.Sprintf("Too many failed sign-in attempts. Try again in %d seconds.", int(math.Ceil(wait.Seconds()))))
		return
	}
	u, err := s.store.UserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, r, err)
		return
	}
	if u == nil || u.PasswordHash == "" || u.Disabled {
		secret.BurnPasswordCheck(req.Password)
	}
	if u == nil || u.PasswordHash == "" || u.Disabled || !secret.VerifyPassword(u.PasswordHash, req.Password) {
		s.logins.fail(email, ip)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Incorrect email or password")
		return
	}
	s.logins.succeed(email, ip)
	s.issueSession(w, r, u)
}

// POST /auth/logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *store.User) {
	if err := s.store.DeleteAuthToken(r.Context(), secret.Hash(bearerToken(r))); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okBody)
}

// POST /auth/request-reset
func (s *Server) requestReset(w http.ResponseWriter, r *http.Request) {
	s.requestEmailToken(w, r, store.PurposeReset, resetTTL, "Reset your password",
		"Someone asked to reset the password for this account. Paste this reset code into the app to choose a new password:")
}

// POST /auth/request-login
func (s *Server) requestLogin(w http.ResponseWriter, r *http.Request) {
	s.requestEmailToken(w, r, store.PurposeLogin, loginTTL, "Your sign-in code",
		"Paste this one-time sign-in code into the app:")
}

// requestEmailToken emails a single-use token to an existing, enabled
// account. The response is identical whether or not one was sent.
func (s *Server) requestEmailToken(w http.ResponseWriter, r *http.Request, purpose string, ttl time.Duration, subject, intro string) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	email := NormalizeEmail(req.Email)
	if email != "" && s.emailLimit.allow(email) {
		u, err := s.store.UserByEmail(r.Context(), email)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, r, err)
			return
		}
		if u != nil && !u.Disabled {
			tok, err := s.store.NewEmailCode(r.Context(), email, purpose, ttl)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			s.sendMail(email, subject, tokenEmail(s.cfg.ServerName, intro, tok, ttl))
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent_if_registered"})
}

// POST /auth/reset-with-token
func (s *Server) resetWithToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResetToken string `json:"reset_token"`
		Password   string `json:"password"`
	}
	if !decode(w, r, &req) || !checkPassword(w, req.Password) {
		return
	}
	bearer := secret.NewToken(32)
	email, err := s.store.ResetPassword(r.Context(), secret.Hash(strings.TrimSpace(req.ResetToken)),
		secret.HashPassword(req.Password), secret.Hash(bearer))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "invalid_token", "That reset code is invalid, expired or already used")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.logins.clearEmail(email)
	writeJSON(w, http.StatusOK, authTokenResp{Token: bearer, Email: email})
}

// POST /auth/login-with-link
func (s *Server) loginWithLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginToken string `json:"login_token"`
	}
	if !decode(w, r, &req) {
		return
	}
	bearer := secret.NewToken(32)
	email, err := s.store.LoginWithLink(r.Context(), secret.Hash(strings.TrimSpace(req.LoginToken)), secret.Hash(bearer))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "invalid_token", "That sign-in code is invalid, expired or already used")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, authTokenResp{Token: bearer, Email: email})
}

// ---------------------------------------------------------------------------

func checkPassword(w http.ResponseWriter, pw string) bool {
	if len([]rune(pw)) < minPasswordLen {
		writeError(w, http.StatusBadRequest, "weak_password", fmt.Sprintf("Password must be at least %d characters", minPasswordLen))
		return false
	}
	if len(pw) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "bad_password", "Password is too long")
		return false
	}
	return true
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	bearer := secret.NewToken(32)
	if err := s.store.CreateAuthToken(r.Context(), u.ID, secret.Hash(bearer)); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, authTokenResp{Token: bearer, Email: u.Email})
}

// sendMail delivers in the background: the response must not wait on SMTP,
// and its timing must not reveal whether an email was sent.
func (s *Server) sendMail(to, subject, body string) {
	go func() {
		if err := s.mail.Send(to, s.cfg.ServerName+": "+subject, body); err != nil {
			s.log.Error("send email", "to", to, "err", err)
		}
	}()
}

func tokenEmail(server, intro, tok string, ttl time.Duration) string {
	return fmt.Sprintf("%s\n\n    %s\n\nThis code expires in %s and can be used once.\n"+
		"If you didn't request it, you can ignore this email.\n\n-- %s\n",
		intro, tok, humanDuration(ttl), server)
}

func humanDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}
