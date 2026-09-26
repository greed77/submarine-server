package store

import (
	"context"
	"database/sql"
	"errors"
)

// Share roles and member statuses.
const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleUser   = "user" // read-only viewer

	StatusPending = "pending"
	StatusActive  = "active"
)

type Membership struct {
	Role      string
	Status    string
	SealedDEK string
}

type ShareInfo struct {
	ShareID    string
	Name       string
	Role       string
	Status     string
	OwnerEmail string
}

type MemberInfo struct {
	UserID int64
	Email  string
	Role   string
	Status string
}

// UpsertShare creates a share owned by ownerID, or — if ownerID already owns
// it — updates its name and the owner's sealed DEK. A share owned by someone
// else yields ErrForbidden.
func (s *Store) UpsertShare(ctx context.Context, shareID string, ownerID int64, name, sealedDEK string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		now := s.nowMS()
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT owner_user_id FROM shares WHERE share_id = ?`, shareID).Scan(&owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO shares (share_id, owner_user_id, name, created_at) VALUES (?, ?, ?, ?)`,
				shareID, ownerID, name, now); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO share_members (share_id, user_id, role, status, sealed_dek, invited_at, accepted_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				shareID, ownerID, RoleOwner, StatusActive, sealedDEK, now, now)
			return err
		case err != nil:
			return err
		case owner != ownerID:
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `UPDATE shares SET name = ? WHERE share_id = ?`, name, shareID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE share_members SET sealed_dek = ? WHERE share_id = ? AND user_id = ?`,
			sealedDEK, shareID, ownerID)
		return err
	})
}

// ShareOwner returns the owner of a share, or ErrNotFound.
func (s *Store) ShareOwner(ctx context.Context, shareID string) (int64, error) {
	var owner int64
	err := s.db.QueryRowContext(ctx, `SELECT owner_user_id FROM shares WHERE share_id = ?`, shareID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return owner, err
}

// UpsertMember adds a pending member, or for an existing member replaces the
// role and sealed DEK while keeping the status (key rotation re-invites
// active members and must not reset them to pending).
func (s *Store) UpsertMember(ctx context.Context, shareID string, userID int64, role, sealedDEK string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO share_members (share_id, user_id, role, status, sealed_dek, invited_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (share_id, user_id) DO UPDATE SET
			role = excluded.role,
			sealed_dek = excluded.sealed_dek`,
		shareID, userID, role, StatusPending, sealedDEK, s.nowMS())
	return err
}

func (s *Store) Membership(ctx context.Context, shareID string, userID int64) (*Membership, error) {
	var m Membership
	err := s.db.QueryRowContext(ctx,
		`SELECT role, status, sealed_dek FROM share_members WHERE share_id = ? AND user_id = ?`, shareID, userID).
		Scan(&m.Role, &m.Status, &m.SealedDEK)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

// SharesFor lists every share the user belongs to, owned ones included.
func (s *Store) SharesFor(ctx context.Context, userID int64) ([]ShareInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.share_id, s.name, m.role, m.status, o.email
		FROM share_members m
		JOIN shares s ON s.share_id = m.share_id
		JOIN users o ON o.id = s.owner_user_id
		WHERE m.user_id = ?
		ORDER BY s.name, s.share_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ShareInfo{}
	for rows.Next() {
		var i ShareInfo
		if err := rows.Scan(&i.ShareID, &i.Name, &i.Role, &i.Status, &i.OwnerEmail); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Members lists a share's roster, owner first.
func (s *Store) Members(ctx context.Context, shareID string) ([]MemberInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.user_id, u.email, m.role, m.status
		FROM share_members m JOIN users u ON u.id = m.user_id
		WHERE m.share_id = ?
		ORDER BY m.role <> 'owner', m.invited_at, u.email`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MemberInfo{}
	for rows.Next() {
		var m MemberInfo
		if err := rows.Scan(&m.UserID, &m.Email, &m.Role, &m.Status); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AcceptInvite marks a membership active (idempotently) and returns it.
func (s *Store) AcceptInvite(ctx context.Context, shareID string, userID int64) (*Membership, error) {
	var m Membership
	err := s.db.QueryRowContext(ctx, `
		UPDATE share_members
		SET status = ?, accepted_at = COALESCE(accepted_at, ?)
		WHERE share_id = ? AND user_id = ?
		RETURNING role, status, sealed_dek`,
		StatusActive, s.nowMS(), shareID, userID).Scan(&m.Role, &m.Status, &m.SealedDEK)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

// SetMemberRole changes a non-owner member's role.
func (s *Store) SetMemberRole(ctx context.Context, shareID string, userID int64, role string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE share_members SET role = ? WHERE share_id = ? AND user_id = ? AND role <> 'owner'`,
		role, shareID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveMember deletes a non-owner membership (revoke or leave).
func (s *Store) RemoveMember(ctx context.Context, shareID string, userID int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM share_members WHERE share_id = ? AND user_id = ? AND role <> 'owner'`, shareID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteShare removes a share with all its memberships and records.
func (s *Store) DeleteShare(ctx context.Context, shareID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE share_id = ?`, shareID)
	return err
}
