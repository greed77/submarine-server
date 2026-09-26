package api

import (
	"errors"
	"net/http"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

// POST /keys/publish
func (s *Server) keysPublish(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		PublicKey      string `json:"public_key"`
		WrappedPrivkey string `json:"wrapped_privkey"`
		EncSalt        string `json:"enc_salt"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !validLen(req.PublicKey, 1, 256) || !validLen(req.WrappedPrivkey, 1, 100_000) || !validLen(req.EncSalt, 1, 256) {
		writeError(w, http.StatusBadRequest, "invalid_keys", "public_key, wrapped_privkey and enc_salt are required")
		return
	}
	created, rotated, err := s.store.PublishKeys(r.Context(), u.ID,
		store.Keys{PublicKey: req.PublicKey, WrappedPrivkey: req.WrappedPrivkey, EncSalt: req.EncSalt})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if rotated {
		s.log.Info("identity key rotated", "user_id", u.ID)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"created": created, "rotated": rotated})
}

// GET /keys/me
func (s *Server) keysMe(w http.ResponseWriter, r *http.Request, u *store.User) {
	k, err := s.store.KeysFor(r.Context(), u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]bool{"exists": false})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exists":          true,
		"public_key":      k.PublicKey,
		"wrapped_privkey": k.WrappedPrivkey,
		"enc_salt":        k.EncSalt,
	})
}

// POST /keys/lookup — 404 covers both "no such user" and "no key", so the
// endpoint can't be used to enumerate accounts.
func (s *Server) keysLookup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.lookupLimit.allow(u.Email) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many lookups; try again shortly")
		return
	}
	id, email, pub, err := s.store.LookupPublicKey(r.Context(), NormalizeEmail(req.Email))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "No shareable user with that email")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": id, "email": email, "public_key": pub})
}
