package store

import (
	"context"
	"database/sql"
	"time"
)

// Read-only queries behind the admin CLI and web UI. Byte counts are decoded
// blob sizes (what the client actually stored), not hex text lengths.

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

// UserStats returns every user, ordered by email.
func (s *Store) UserStats(ctx context.Context) ([]UserStats, error) {
	return s.userStats(ctx, 0)
}

// UserStat returns one user, or ErrNotFound.
func (s *Store) UserStat(ctx context.Context, userID int64) (*UserStats, error) {
	out, err := s.userStats(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return &out[0], nil
}

// userStats lists all users, or just userID when it is non-zero.
func (s *Store) userStats(ctx context.Context, userID int64) ([]UserStats, error) {
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
			FROM sync_records WHERE ?1 = 0 OR user_id = ?1 GROUP BY user_id
		) p ON p.user_id = u.id
		WHERE ?1 = 0 OR u.id = ?1
		ORDER BY u.email`, userID)
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

type ProfileStats struct {
	Profile     string
	Name        string
	Records     int64
	Live        int64 // excludes tombstones and the escrow record
	Tombstones  int64
	Bytes       int64
	LastUpdated time.Time
}

// ProfileStats summarizes each of a user's personal partitions, largest first.
func (s *Store) ProfileStats(ctx context.Context, userID int64) ([]ProfileStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.profile, COALESCE(n.name, r.profile), COUNT(*),
		       SUM(CASE WHEN r.deleted = 0 AND r.entity_type <> 'dek_escrow' THEN 1 ELSE 0 END),
		       SUM(r.deleted), SUM(r.blob_bytes), MAX(r.server_modified_at)
		FROM sync_records r
		LEFT JOIN sync_profile_names n ON n.user_id = r.user_id AND n.profile = r.profile
		WHERE r.user_id = ?
		GROUP BY r.profile
		ORDER BY SUM(r.blob_bytes) DESC, r.profile`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileStats
	for rows.Next() {
		var p ProfileStats
		var last int64
		if err := rows.Scan(&p.Profile, &p.Name, &p.Records, &p.Live, &p.Tombstones, &p.Bytes, &last); err != nil {
			return nil, err
		}
		p.LastUpdated = msToTime(last)
		out = append(out, p)
	}
	return out, rows.Err()
}

type Session struct {
	CreatedAt time.Time
	LastUsed  time.Time
}

// Sessions lists a user's live bearer tokens (one per signed-in device),
// most recently used first. Tokens themselves are never readable.
func (s *Store) Sessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT created_at, last_used_at FROM auth_tokens WHERE user_id = ? ORDER BY last_used_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var created, used int64
		if err := rows.Scan(&created, &used); err != nil {
			return nil, err
		}
		out = append(out, Session{msToTime(created), msToTime(used)})
	}
	return out, rows.Err()
}

type ShareStats struct {
	ShareID      string
	Name         string
	OwnerID      int64
	OwnerEmail   string
	CreatedAt    time.Time
	Members      int64 // including the owner
	Pending      int64
	Records      int64
	Tombstones   int64
	Bytes        int64
	LastModified time.Time // zero if nothing synced yet
}

// ShareStats lists every share, largest first.
func (s *Store) ShareStats(ctx context.Context) ([]ShareStats, error) {
	return s.shareStats(ctx, "")
}

// ShareStat returns one share, or ErrNotFound.
func (s *Store) ShareStat(ctx context.Context, shareID string) (*ShareStats, error) {
	out, err := s.shareStats(ctx, shareID)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return &out[0], nil
}

func (s *Store) shareStats(ctx context.Context, shareID string) ([]ShareStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.share_id, s.name, s.owner_user_id, u.email, s.created_at,
		       (SELECT COUNT(*) FROM share_members m WHERE m.share_id = s.share_id),
		       (SELECT COUNT(*) FROM share_members m WHERE m.share_id = s.share_id AND m.status = 'pending'),
		       COALESCE(r.records, 0), COALESCE(r.tombstones, 0), COALESCE(r.bytes, 0), r.last_modified
		FROM shares s
		JOIN users u ON u.id = s.owner_user_id
		LEFT JOIN (
			SELECT share_id, COUNT(*) AS records, SUM(deleted) AS tombstones,
			       SUM(blob_bytes) AS bytes, MAX(server_modified_at) AS last_modified
			FROM shared_records WHERE ?1 = '' OR share_id = ?1 GROUP BY share_id
		) r ON r.share_id = s.share_id
		WHERE ?1 = '' OR s.share_id = ?1
		ORDER BY COALESCE(r.bytes, 0) DESC, s.name`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareStats
	for rows.Next() {
		var sh ShareStats
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&sh.ShareID, &sh.Name, &sh.OwnerID, &sh.OwnerEmail, &created,
			&sh.Members, &sh.Pending, &sh.Records, &sh.Tombstones, &sh.Bytes, &last); err != nil {
			return nil, err
		}
		sh.CreatedAt = msToTime(created)
		if last.Valid {
			sh.LastModified = msToTime(last.Int64)
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

// DBSize is the size of the main database file in bytes (excluding the WAL).
func (s *Store) DBSize(ctx context.Context) (int64, error) {
	var pages, size int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&size); err != nil {
		return 0, err
	}
	return pages * size, nil
}
