package store

import (
	"context"
	"database/sql"
	"errors"
)

type Keys struct {
	PublicKey      string
	WrappedPrivkey string
	EncSalt        string
}

// PublishKeys upserts the user's identity key. created reports that no key
// existed; rotated that one existed with a different public key.
func (s *Store) PublishKeys(ctx context.Context, userID int64, k Keys) (created, rotated bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var old string
		err := tx.QueryRowContext(ctx, `SELECT public_key FROM user_keys WHERE user_id = ?`, userID).Scan(&old)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			created = true
		case err != nil:
			return err
		default:
			rotated = old != k.PublicKey
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO user_keys (user_id, public_key, wrapped_privkey, enc_salt, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (user_id) DO UPDATE SET
				public_key = excluded.public_key,
				wrapped_privkey = excluded.wrapped_privkey,
				enc_salt = excluded.enc_salt,
				updated_at = excluded.updated_at`,
			userID, k.PublicKey, k.WrappedPrivkey, k.EncSalt, s.nowMS())
		return err
	})
	return created, rotated, err
}

func (s *Store) KeysFor(ctx context.Context, userID int64) (*Keys, error) {
	var k Keys
	err := s.db.QueryRowContext(ctx,
		`SELECT public_key, wrapped_privkey, enc_salt FROM user_keys WHERE user_id = ?`, userID).
		Scan(&k.PublicKey, &k.WrappedPrivkey, &k.EncSalt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

// LookupPublicKey finds an enabled user with a published key by email.
// Unknown users and users without a key are both ErrNotFound.
func (s *Store) LookupPublicKey(ctx context.Context, email string) (userID int64, canonical, publicKey string, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, k.public_key
		FROM users u JOIN user_keys k ON k.user_id = u.id
		WHERE u.email = ? AND u.disabled = 0`, email).Scan(&userID, &canonical, &publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}
