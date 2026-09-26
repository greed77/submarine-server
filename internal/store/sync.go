package store

import (
	"context"
	"database/sql"
	"time"
)

// Record is one opaque sync entity, shared by personal and shared sync.
type Record struct {
	UUID       string  `json:"uuid"`
	EntityType string  `json:"entity_type"`
	UpdatedAt  string  `json:"updated_at"`
	Deleted    bool    `json:"deleted"`
	Blob       *string `json:"blob,omitempty"`
}

func blobBytes(r Record) int {
	if r.Blob == nil {
		return 0
	}
	return len(*r.Blob) / 2
}

// Last-Write-Wins upserts. The WHERE uses >= deliberately: key rotation and
// escrow refresh re-push identical updated_at stamps with new blobs and rely
// on them replacing the stored row (spec §5.1).
const (
	upsertPersonal = `
		INSERT INTO sync_records
			(user_id, profile, uuid, entity_type, updated_at, deleted, blob, blob_bytes, server_modified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, profile, uuid) DO UPDATE SET
			entity_type = excluded.entity_type,
			updated_at = excluded.updated_at,
			deleted = excluded.deleted,
			blob = excluded.blob,
			blob_bytes = excluded.blob_bytes,
			server_modified_at = excluded.server_modified_at
		WHERE excluded.updated_at >= sync_records.updated_at`

	upsertShared = `
		INSERT INTO shared_records
			(share_id, uuid, entity_type, updated_at, deleted, blob, blob_bytes, last_writer_user_id, server_modified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (share_id, uuid) DO UPDATE SET
			entity_type = excluded.entity_type,
			updated_at = excluded.updated_at,
			deleted = excluded.deleted,
			blob = excluded.blob,
			blob_bytes = excluded.blob_bytes,
			last_writer_user_id = excluded.last_writer_user_id,
			server_modified_at = excluded.server_modified_at
		WHERE excluded.updated_at >= shared_records.updated_at`
)

// MergePersonal applies incoming records to the caller's partition and, when
// name is non-empty, records the partition's display name. Callers must not
// call it with zero records: an empty push is a pure read.
func (s *Store) MergePersonal(ctx context.Context, userID int64, profile, name string, recs []Record) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, upsertPersonal)
		if err != nil {
			return err
		}
		defer stmt.Close()
		now := s.nowMS()
		for _, r := range recs {
			if _, err := stmt.ExecContext(ctx, userID, profile, r.UUID, r.EntityType, r.UpdatedAt,
				r.Deleted, r.Blob, blobBytes(r), now); err != nil {
				return err
			}
		}
		if name != "" {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO sync_profile_names (user_id, profile, name) VALUES (?, ?, ?)
				ON CONFLICT (user_id, profile) DO UPDATE SET name = excluded.name`,
				userID, profile, name)
		}
		return err
	})
}

// MergeShared applies incoming records to a share's partition.
func (s *Store) MergeShared(ctx context.Context, shareID string, writerID int64, recs []Record) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, upsertShared)
		if err != nil {
			return err
		}
		defer stmt.Close()
		now := s.nowMS()
		for _, r := range recs {
			if _, err := stmt.ExecContext(ctx, shareID, r.UUID, r.EntityType, r.UpdatedAt,
				r.Deleted, r.Blob, blobBytes(r), writerID, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// StreamPersonal calls fn for every record in the partition stamped after
// since, without buffering the whole partition in memory.
func (s *Store) StreamPersonal(ctx context.Context, userID int64, profile, since string, fn func(Record) error) error {
	return s.stream(ctx, fn, `
		SELECT uuid, entity_type, updated_at, deleted, blob FROM sync_records
		WHERE user_id = ? AND profile = ? AND updated_at > ?`, userID, profile, since)
}

func (s *Store) StreamShared(ctx context.Context, shareID, since string, fn func(Record) error) error {
	return s.stream(ctx, fn, `
		SELECT uuid, entity_type, updated_at, deleted, blob FROM shared_records
		WHERE share_id = ? AND updated_at > ?`, shareID, since)
}

func (s *Store) stream(ctx context.Context, fn func(Record) error, q string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r Record
		var blob sql.NullString
		if err := rows.Scan(&r.UUID, &r.EntityType, &r.UpdatedAt, &r.Deleted, &blob); err != nil {
			return err
		}
		if blob.Valid {
			r.Blob = &blob.String
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

type ProfileInfo struct {
	Profile     string
	Name        string
	Records     int64
	LiveRecords int64
	LastUpdated time.Time
}

// ListProfiles summarizes each of the user's personal partitions.
func (s *Store) ListProfiles(ctx context.Context, userID int64) ([]ProfileInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.profile, COALESCE(n.name, r.profile), COUNT(*),
		       SUM(CASE WHEN r.deleted = 0 AND r.entity_type <> 'dek_escrow' THEN 1 ELSE 0 END),
		       MAX(r.server_modified_at)
		FROM sync_records r
		LEFT JOIN sync_profile_names n ON n.user_id = r.user_id AND n.profile = r.profile
		WHERE r.user_id = ?
		GROUP BY r.profile
		ORDER BY r.profile`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileInfo{}
	for rows.Next() {
		var p ProfileInfo
		var last int64
		if err := rows.Scan(&p.Profile, &p.Name, &p.Records, &p.LiveRecords, &last); err != nil {
			return nil, err
		}
		p.LastUpdated = msToTime(last)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePartition hard-deletes a personal partition and its display name.
// A partition that doesn't exist deletes 0 rows and is not an error.
func (s *Store) DeletePartition(ctx context.Context, userID int64, profile string) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sync_records WHERE user_id = ? AND profile = ?`, userID, profile)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		_, err = tx.ExecContext(ctx, `DELETE FROM sync_profile_names WHERE user_id = ? AND profile = ?`, userID, profile)
		return err
	})
	return n, err
}
