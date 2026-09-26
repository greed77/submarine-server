package api

import (
	"errors"
	"net/http"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

const maxSealedDEK = 8192

type shareReq struct {
	ShareID string `json:"share_id"`
}

// decodeShare decodes a body carrying at least share_id into v and checks it.
func decodeShare(w http.ResponseWriter, r *http.Request, v any, shareID *string) bool {
	if !decode(w, r, v) {
		return false
	}
	if !validLen(*shareID, 16, 64) {
		writeError(w, http.StatusBadRequest, "invalid_share_id", "share_id must be 16-64 characters")
		return false
	}
	return true
}

// requireOwner writes 404/403 and returns false unless u owns the share.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, shareID string, u *store.User) bool {
	owner, err := s.store.ShareOwner(r.Context(), shareID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "share_not_found", "No such share")
	case err != nil:
		s.internalError(w, r, err)
	case owner != u.ID:
		writeError(w, http.StatusForbidden, "not_owner", "Only the share owner can do that")
	default:
		return true
	}
	return false
}

// membership writes 404 and returns nil unless u is a member of the share.
// Non-members can't tell a missing share from one they aren't in.
func (s *Server) membership(w http.ResponseWriter, r *http.Request, shareID string, u *store.User) *store.Membership {
	m, err := s.store.Membership(r.Context(), shareID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_member", "You are not a member of that share")
		return nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return nil
	}
	return m
}

func validMemberRole(role string) bool { return role == store.RoleEditor || role == store.RoleUser }

// POST /shares/create — upsert: creates the share, or lets its owner rename
// it and re-seal their own DEK (key rotation).
func (s *Server) sharesCreate(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		ShareID   string `json:"share_id"`
		Name      string `json:"name"`
		SealedDEK string `json:"sealed_dek"`
	}
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if !validName(req.Name, 1) {
		writeError(w, http.StatusBadRequest, "invalid_name", "name must be 1-64 characters")
		return
	}
	if !validLen(req.SealedDEK, 1, maxSealedDEK) {
		writeError(w, http.StatusBadRequest, "invalid_sealed_dek", "sealed_dek is required")
		return
	}
	err := s.store.UpsertShare(r.Context(), req.ShareID, u.ID, req.Name, req.SealedDEK)
	if errors.Is(err, store.ErrForbidden) {
		writeError(w, http.StatusForbidden, "not_owner", "That share belongs to someone else")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okBody)
}

// POST /shares/invite — upsert: a re-invite replaces role and sealed DEK but
// keeps the member's status.
func (s *Server) sharesInvite(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		ShareID   string `json:"share_id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		SealedDEK string `json:"sealed_dek"`
	}
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if !validMemberRole(req.Role) {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be editor or user")
		return
	}
	if !validLen(req.SealedDEK, 1, maxSealedDEK) {
		writeError(w, http.StatusBadRequest, "invalid_sealed_dek", "sealed_dek is required")
		return
	}
	if !s.requireOwner(w, r, req.ShareID, u) {
		return
	}
	target, err := s.store.UserByEmail(r.Context(), NormalizeEmail(req.Email))
	if errors.Is(err, store.ErrNotFound) || (err == nil && target.Disabled) {
		writeError(w, http.StatusNotFound, "user_not_found", "No user with that email")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if target.ID == u.ID {
		writeError(w, http.StatusBadRequest, "invite_self", "You already own this share")
		return
	}
	if err := s.store.UpsertMember(r.Context(), req.ShareID, target.ID, req.Role, req.SealedDEK); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"member_user_id": target.ID})
}

// POST /shares/list
func (s *Server) sharesList(w http.ResponseWriter, r *http.Request, u *store.User) {
	shares, err := s.store.SharesFor(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	type entry struct {
		ShareID    string `json:"share_id"`
		Name       string `json:"name"`
		Role       string `json:"role"`
		Status     string `json:"status"`
		OwnerEmail string `json:"owner_email"`
	}
	out := make([]entry, len(shares))
	for i, sh := range shares {
		out[i] = entry{sh.ShareID, sh.Name, sh.Role, sh.Status, sh.OwnerEmail}
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

// POST /shares/dek — called before every shared sync, so it is a single
// primary-key lookup.
func (s *Server) sharesDEK(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req shareReq
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if m := s.membership(w, r, req.ShareID, u); m != nil {
		writeJSON(w, http.StatusOK, map[string]string{"role": m.Role, "status": m.Status, "sealed_dek": m.SealedDEK})
	}
}

// POST /shares/members
func (s *Server) sharesMembers(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req shareReq
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if s.membership(w, r, req.ShareID, u) == nil {
		return
	}
	members, err := s.store.Members(r.Context(), req.ShareID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	type entry struct {
		UserID int64  `json:"user_id"`
		Email  string `json:"email"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	out := make([]entry, len(members))
	for i, m := range members {
		out[i] = entry{m.UserID, m.Email, m.Role, m.Status}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

// POST /shares/accept — idempotent.
func (s *Server) sharesAccept(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req shareReq
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	m, err := s.store.AcceptInvite(r.Context(), req.ShareID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_member", "You have no invite to that share")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"role": m.Role, "sealed_dek": m.SealedDEK})
}

// POST /shares/set-role
func (s *Server) sharesSetRole(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		ShareID      string `json:"share_id"`
		MemberUserID int64  `json:"member_user_id"`
		Role         string `json:"role"`
	}
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if !validMemberRole(req.Role) {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be editor or user")
		return
	}
	if !s.requireOwner(w, r, req.ShareID, u) {
		return
	}
	if req.MemberUserID == u.ID {
		writeError(w, http.StatusBadRequest, "owner_role", "The owner's role can't be changed")
		return
	}
	s.memberResult(w, r, s.store.SetMemberRole(r.Context(), req.ShareID, req.MemberUserID, req.Role))
}

// POST /shares/revoke — deletes the membership outright; a later re-invite
// starts fresh as pending.
func (s *Server) sharesRevoke(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		ShareID      string `json:"share_id"`
		MemberUserID int64  `json:"member_user_id"`
	}
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if !s.requireOwner(w, r, req.ShareID, u) {
		return
	}
	if req.MemberUserID == u.ID {
		writeError(w, http.StatusBadRequest, "revoke_owner", "The owner can't be revoked; delete the share instead")
		return
	}
	s.memberResult(w, r, s.store.RemoveMember(r.Context(), req.ShareID, req.MemberUserID))
}

// POST /shares/leave
func (s *Server) sharesLeave(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req shareReq
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	m := s.membership(w, r, req.ShareID, u)
	if m == nil {
		return
	}
	if m.Role == store.RoleOwner {
		writeError(w, http.StatusBadRequest, "owner_leave", "The owner can't leave; delete the share instead")
		return
	}
	s.memberResult(w, r, s.store.RemoveMember(r.Context(), req.ShareID, u.ID))
}

// POST /shares/delete — cascades to memberships and records.
func (s *Server) sharesDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req shareReq
	if !decodeShare(w, r, &req, &req.ShareID) {
		return
	}
	if !s.requireOwner(w, r, req.ShareID, u) {
		return
	}
	if err := s.store.DeleteShare(r.Context(), req.ShareID); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okBody)
}

// POST /shares/sync — same merge rules as /sync; active members only, and
// viewers (role "user") may only pull.
func (s *Server) sharesSync(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		ShareID string         `json:"share_id"`
		Since   string         `json:"since"`
		Records []store.Record `json:"records"`
	}
	if !decodeShare(w, r, &req, &req.ShareID) || !s.validSyncBody(w, req.Since, req.Records) {
		return
	}
	m, err := s.store.Membership(r.Context(), req.ShareID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusForbidden, "not_member", "You are not a member of that share")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if m.Status != store.StatusActive {
		writeError(w, http.StatusForbidden, "not_accepted", "Accept the invite before syncing")
		return
	}
	if len(req.Records) > 0 {
		if m.Role == store.RoleUser {
			writeError(w, http.StatusForbidden, "read_only", "You have read-only access to this share")
			return
		}
		if err := s.store.MergeShared(r.Context(), req.ShareID, u.ID, req.Records); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.writeRecords(w, r, func(fn func(store.Record) error) error {
		return s.store.StreamShared(r.Context(), req.ShareID, req.Since, fn)
	})
}

func (s *Server) memberResult(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_member", "That user is not a member of this share")
	case err != nil:
		s.internalError(w, r, err)
	default:
		writeJSON(w, http.StatusOK, okBody)
	}
}
