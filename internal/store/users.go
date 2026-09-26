package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type User struct {
	ID           int64
	Email        string
	PasswordHash string // empty when no password has been set yet
	Disabled     bool
}

// touchInterval throttles last-used bookkeeping so an active device costs at
// most one small write per minute rather than one per request.
const touchInterval = time.Minute

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var pw sql.NullString
	err := row.Scan(&u.ID, &u.Email, &pw, &u.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.PasswordHash = pw.String
	return &u, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, disabled FROM users WHERE email = ?`, email))
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, disabled FROM users WHERE id = ?`, id))
}

// UserByToken resolves a bearer token hash to its (enabled) user and records
// the access time.
func (s *Store) UserByToken(ctx context.Context, tokenHash []byte) (*User, error) {
	var u User
	var lastUsed int64
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.disabled, t.last_used_at
		FROM auth_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND u.disabled = 0`, tokenHash).
		Scan(&u.ID, &u.Email, &u.Disabled, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := s.nowMS()
	if now-lastUsed >= touchInterval.Milliseconds() {
		// Best effort: a failed touch must not fail the request.
		s.db.ExecContext(ctx, `UPDATE auth_tokens SET last_used_at = ? WHERE token_hash = ?`, now, tokenHash)
		s.db.ExecContext(ctx, `UPDATE users SET last_seen_at = ? WHERE id = ?`, now, u.ID)
	}
	return &u, nil
}

// CreateUser inserts a user with no password. It returns ErrConflict if the
// email is taken.
func (s *Store) CreateUser(ctx context.Context, email string) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)`, email).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO users (email, created_at) VALUES (?, ?)`, email, s.nowMS())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// SetDisabled enables or disables a user. Disabling also revokes every token,
// so the user's devices are signed out on their next request.
func (s *Store) SetDisabled(ctx context.Context, userID int64, disabled bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if disabled {
			_, err = tx.ExecContext(ctx, `DELETE FROM auth_tokens WHERE user_id = ?`, userID)
		}
		return err
	})
}

// DeleteUser removes a user and, by cascade, their tokens, keys, personal
// records, memberships and every share they own.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeUserTokens signs out every device of a user.
func (s *Store) RevokeUserTokens(ctx context.Context, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) IsAllowlisted(ctx context.Context, email string) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM signup_allowlist WHERE email = ?)`, email).Scan(&ok)
	return ok, err
}

func (s *Store) AllowlistAdd(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO signup_allowlist (email, added_at) VALUES (?, ?) ON CONFLICT DO NOTHING`, email, s.nowMS())
	return err
}

func (s *Store) AllowlistRemove(ctx context.Context, email string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM signup_allowlist WHERE email = ?`, email)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) Allowlist(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email FROM signup_allowlist ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
