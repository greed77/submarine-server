package store

import (
	"context"
	"database/sql"
	"time"
)

// UserStats is one row of the admin overview. It is shared by the CLI and
// (later) the admin web UI. Byte counts are decoded blob sizes.
type UserStats struct {
	ID            int64
	Email         string
	CreatedAt     time.Time
	LastSeen      time.Time // zero if never
	Disabled      bool
	HasPassword   bool
	HasKey        bool
	Devices       int64 // live bearer tokens
	Profiles      int64
	Records       int64
	Tombstones    int64
	PersonalBytes int64
	OwnedShares   int64
	SharedBytes   int64 // records in shares this user owns
}

func (u UserStats) TotalBytes() int64 { return u.PersonalBytes + u.SharedBytes }

func (s *Store) UserStats(ctx context.Context) ([]UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.email, u.created_at,
		       -- last_seen_at is only touched once a session is a minute old,
		       -- so fold in token times to count fresh sign-ins too.
		       NULLIF(MAX(COALESCE(u.last_seen_at, 0),
		                  COALESCE((SELECT MAX(t.last_used_at) FROM auth_tokens t WHERE t.user_id = u.id), 0)), 0),
		       u.disabled,
		       u.password_hash IS NOT NULL,
		       EXISTS (SELECT 1 FROM user_keys k WHERE k.user_id = u.id),
		       (SELECT COUNT(*) FROM auth_tokens t WHERE t.user_id = u.id),
		       COALESCE(p.profiles, 0), COALESCE(p.records, 0), COALESCE(p.tombstones, 0), COALESCE(p.bytes, 0),
		       (SELECT COUNT(*) FROM shares s WHERE s.owner_user_id = u.id),
		       (SELECT COALESCE(SUM(r.blob_bytes), 0)
		          FROM shares s JOIN shared_records r ON r.share_id = s.share_id
		         WHERE s.owner_user_id = u.id)
		FROM users u
		LEFT JOIN (
			SELECT user_id, COUNT(DISTINCT profile) AS profiles, COUNT(*) AS records,
			       SUM(deleted) AS tombstones, SUM(blob_bytes) AS bytes
			FROM sync_records GROUP BY user_id
		) p ON p.user_id = u.id
		ORDER BY u.email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserStats
	for rows.Next() {
		var u UserStats
		var created int64
		var lastSeen sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Email, &created, &lastSeen, &u.Disabled, &u.HasPassword, &u.HasKey,
			&u.Devices, &u.Profiles, &u.Records, &u.Tombstones, &u.PersonalBytes,
			&u.OwnedShares, &u.SharedBytes); err != nil {
			return nil, err
		}
		u.CreatedAt = msToTime(created)
		if lastSeen.Valid {
			u.LastSeen = msToTime(lastSeen.Int64)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
