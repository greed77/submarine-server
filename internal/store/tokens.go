package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Email token purposes.
const (
	PurposeVerify = "verify" // sign-up: proves control of the email
	PurposeClaim  = "claim"  // issued by /auth/verify, spent by /auth/set-password
	PurposeReset  = "reset"
	PurposeLogin  = "login" // magic link
)

func (s *Store) CreateAuthToken(ctx context.Context, userID int64, tokenHash []byte) error {
	now := s.nowMS()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_tokens (token_hash, user_id, created_at, last_used_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, now, now)
	return err
}

func (s *Store) DeleteAuthToken(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_tokens WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) CreateEmailToken(ctx context.Context, tokenHash []byte, email, purpose string, ttl time.Duration) error {
	now := s.nowMS()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO email_tokens (token_hash, email, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		tokenHash, email, purpose, now, now+ttl.Milliseconds())
	return err
}

// consumeEmailToken marks a live token used and returns its email. Missing,
// expired and already-used tokens all yield ErrNotFound.
func (s *Store) consumeEmailToken(ctx context.Context, tx *sql.Tx, tokenHash []byte, purpose string) (string, error) {
	now := s.nowMS()
	var email string
	err := tx.QueryRowContext(ctx, `
		UPDATE email_tokens SET used_at = ?
		WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
		RETURNING email`, now, tokenHash, purpose, now).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

// ExchangeVerifyToken spends a verify token and issues a claim token for the
// same email, atomically.
func (s *Store) ExchangeVerifyToken(ctx context.Context, verifyHash, claimHash []byte, claimTTL time.Duration) (string, error) {
	var email string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if email, err = s.consumeEmailToken(ctx, tx, verifyHash, PurposeVerify); err != nil {
			return err
		}
		now := s.nowMS()
		_, err = tx.ExecContext(ctx,
			`INSERT INTO email_tokens (token_hash, email, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
			claimHash, email, PurposeClaim, now, now+claimTTL.Milliseconds())
		return err
	})
	return email, err
}

// ClaimAccount spends a claim token, creates the user (or sets the password
// on a user that has none yet) and issues a bearer token. A user that already
// has a password yields ErrConflict: sign-up must never act as a reset.
func (s *Store) ClaimAccount(ctx context.Context, claimHash []byte, passwordHash string, authHash []byte) (string, error) {
	var email string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if email, err = s.consumeEmailToken(ctx, tx, claimHash, PurposeClaim); err != nil {
			return err
		}
		now := s.nowMS()
		var id int64
		var existing sql.NullString
		var disabled bool
		err = tx.QueryRowContext(ctx, `SELECT id, password_hash, disabled FROM users WHERE email = ?`, email).
			Scan(&id, &existing, &disabled)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			res, err := tx.ExecContext(ctx,
				`INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)`, email, passwordHash, now)
			if err != nil {
				return err
			}
			if id, err = res.LastInsertId(); err != nil {
				return err
			}
		case err != nil:
			return err
		case existing.Valid || disabled:
			return ErrConflict
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO auth_tokens (token_hash, user_id, created_at, last_used_at) VALUES (?, ?, ?, ?)`,
			authHash, id, now, now)
		return err
	})
	return email, err
}

// ResetPassword spends a reset token, sets the new password, signs out every
// other device, voids other outstanding reset tokens, and issues a fresh
// bearer token.
func (s *Store) ResetPassword(ctx context.Context, resetHash []byte, passwordHash string, authHash []byte) (string, error) {
	var email string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if email, err = s.consumeEmailToken(ctx, tx, resetHash, PurposeReset); err != nil {
			return err
		}
		now := s.nowMS()
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ? AND disabled = 0`, email).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		stmts := []struct {
			q    string
			args []any
		}{
			{`UPDATE users SET password_hash = ? WHERE id = ?`, []any{passwordHash, id}},
			{`DELETE FROM auth_tokens WHERE user_id = ?`, []any{id}},
			{`UPDATE email_tokens SET used_at = ? WHERE email = ? AND purpose = ? AND used_at IS NULL`, []any{now, email, PurposeReset}},
			{`INSERT INTO auth_tokens (token_hash, user_id, created_at, last_used_at) VALUES (?, ?, ?, ?)`, []any{authHash, id, now, now}},
		}
		for _, st := range stmts {
			if _, err := tx.ExecContext(ctx, st.q, st.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return email, err
}

// LoginWithLink spends a magic-link token and issues a bearer token.
func (s *Store) LoginWithLink(ctx context.Context, loginHash, authHash []byte) (string, error) {
	var email string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if email, err = s.consumeEmailToken(ctx, tx, loginHash, PurposeLogin); err != nil {
			return err
		}
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ? AND disabled = 0`, email).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now := s.nowMS()
		_, err = tx.ExecContext(ctx,
			`INSERT INTO auth_tokens (token_hash, user_id, created_at, last_used_at) VALUES (?, ?, ?, ?)`,
			authHash, id, now, now)
		return err
	})
	return email, err
}

// PurgeEmailTokens deletes email tokens that expired more than a day ago.
func (s *Store) PurgeEmailTokens(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM email_tokens WHERE expires_at < ?`,
		s.nowMS()-(24*time.Hour).Milliseconds())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
