package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"code.reedpeople.com/tehgreedo/submarine-server/internal/store"
)

// POST /sync
func (s *Server) sync(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Profile string         `json:"profile"`
		Since   string         `json:"since"`
		Records []store.Record `json:"records"`
		Name    string         `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !validLen(req.Profile, 1, 64) {
		writeError(w, http.StatusBadRequest, "invalid_profile", "profile must be 1-64 characters")
		return
	}
	if !validName(req.Name, 0) {
		writeError(w, http.StatusBadRequest, "invalid_name", "name must be at most 64 characters")
		return
	}
	if !s.validSyncBody(w, req.Since, req.Records) {
		return
	}
	// An empty push is a pure read: it must not create the partition or
	// touch the display name (dry-run diffs and restore peeks rely on this).
	if len(req.Records) > 0 {
		if err := s.store.MergePersonal(r.Context(), u.ID, req.Profile, req.Name, req.Records); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.writeRecords(w, r, func(fn func(store.Record) error) error {
		return s.store.StreamPersonal(r.Context(), u.ID, req.Profile, req.Since, fn)
	})
}

// GET /sync/profiles
func (s *Server) syncProfiles(w http.ResponseWriter, r *http.Request, u *store.User) {
	profiles, err := s.store.ListProfiles(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	type entry struct {
		Profile     string `json:"profile"`
		Name        string `json:"name"`
		Records     int64  `json:"records"`
		LiveRecords int64  `json:"live_records"`
		LastUpdated string `json:"last_updated"`
	}
	out := make([]entry, len(profiles))
	for i, p := range profiles {
		out[i] = entry{p.Profile, p.Name, p.Records, p.LiveRecords, p.LastUpdated.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

// POST /sync/delete
func (s *Server) syncDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Profile string `json:"profile"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !validLen(req.Profile, 1, 64) {
		writeError(w, http.StatusBadRequest, "invalid_profile", "profile must be 1-64 characters")
		return
	}
	n, err := s.store.DeletePartition(r.Context(), u.ID, req.Profile)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

// validSyncBody checks the parts of a sync request shared by /sync and
// /shares/sync. Blobs are opaque; only their size is checked.
func (s *Server) validSyncBody(w http.ResponseWriter, since string, recs []store.Record) bool {
	if len(since) > 64 {
		writeError(w, http.StatusBadRequest, "invalid_since", "since must be at most 64 characters")
		return false
	}
	for i, rec := range recs {
		var problem string
		switch {
		case !validLen(rec.UUID, 1, 64):
			problem = "uuid must be 1-64 characters"
		case !validLen(rec.EntityType, 1, 24):
			problem = "entity_type must be 1-24 characters"
		case !validLen(rec.UpdatedAt, 1, 64):
			problem = "updated_at must be 1-64 characters"
		case rec.Blob != nil && len(*rec.Blob) > s.cfg.MaxBlobChars:
			writeError(w, http.StatusRequestEntityTooLarge, "record_too_large",
				fmt.Sprintf("record %d (%s) exceeds the per-record size limit", i, rec.UUID))
			return false
		}
		if problem != "" {
			writeError(w, http.StatusBadRequest, "invalid_record", fmt.Sprintf("record %d: %s", i, problem))
			return false
		}
	}
	return true
}

// validName reports whether a display name is acceptable: at most 64
// characters, and at least min.
func validName(name string, min int) bool {
	n := utf8.RuneCountInString(name)
	return utf8.ValidString(name) && n >= min && n <= 64
}

// writeRecords streams {"records":[...]} without buffering the partition.
// If the query fails before anything was sent the client gets a normal 500;
// if it fails mid-stream the connection is aborted so the client sees a
// network error rather than a truncated 200.
func (s *Server) writeRecords(w http.ResponseWriter, r *http.Request, stream func(func(store.Record) error) error) {
	bw := bufio.NewWriterSize(w, 64<<10)
	enc := json.NewEncoder(bw)
	n := 0
	err := stream(func(rec store.Record) error {
		if n == 0 {
			w.Header().Set("Content-Type", "application/json")
			bw.WriteString(`{"records":[`)
		} else {
			bw.WriteByte(',')
		}
		n++
		return enc.Encode(rec)
	})
	if err != nil {
		if n == 0 {
			s.internalError(w, r, err)
			return
		}
		s.log.Error("sync stream aborted", "path", r.URL.Path, "err", err)
		panic(http.ErrAbortHandler)
	}
	if n == 0 {
		w.Header().Set("Content-Type", "application/json")
		bw.WriteString(`{"records":[`)
	}
	bw.WriteString("]}\n")
	bw.Flush()
}
