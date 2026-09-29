package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type assemblePackageRequest struct {
	CanID string `json:"can_id"`
	Note  string `json:"note"`
}

type resupplementRequest struct {
	Note string `json:"note"`
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

func verification(err error) map[string]any {
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}
	}
	return map[string]any{"valid": true}
}

// assembleReleasePackage seals a new release evidence package version for the
// current campaign revision and can.
func (s *Server) assembleReleasePackage(w http.ResponseWriter, r *http.Request) {
	var input assemblePackageRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pkg, err := s.plant.AssembleReleasePackage(input.CanID, input.Note)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}

// releasePackages lists every issued version, oldest first.
func (s *Server) releasePackages(w http.ResponseWriter, r *http.Request) {
	packages := s.plant.ReleasePackages()
	summaries := make([]map[string]any, 0, len(packages))
	for _, pkg := range packages {
		summaries = append(summaries, map[string]any{
			"id":         pkg.ID,
			"version":    pkg.Version,
			"can_id":     pkg.CanID,
			"decision":   pkg.Decision,
			"complete":   pkg.Complete(),
			"missing":    pkg.MissingItems(),
			"revoked":    pkg.Revoked,
			"sealed_at":  pkg.SealedAt,
			"supersedes": pkg.Supersedes,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": summaries, "count": len(summaries)})
}

// latestReleasePackage returns the current version together with its seal
// verification result.
func (s *Server) latestReleasePackage(w http.ResponseWriter, r *http.Request) {
	pkg, err := s.plant.LatestReleasePackage()
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}

// releasePackageByVersion returns one delivered version by number.
func (s *Server) releasePackageByVersion(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "version")
	version, err := strconv.Atoi(raw)
	if err != nil || version < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid package version"})
		return
	}
	pkg, err := s.plant.ReleasePackage(version)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}

// releasePackageByID returns one delivered version by its seal ID.
func (s *Server) releasePackageByID(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid package id"})
		return
	}
	pkg, err := s.plant.ReleasePackageByID(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}

// resupplementRelease fills missing evidence and issues a new version; the old
// delivered package still verifies.
func (s *Server) resupplementRelease(w http.ResponseWriter, r *http.Request) {
	var input resupplementRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pkg, err := s.plant.ResupplementRelease(input.Note)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}

// revokeRelease withdraws the current release and issues a revocation version.
func (s *Server) revokeRelease(w http.ResponseWriter, r *http.Request) {
	var input revokeRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pkg, err := s.plant.RevokeRelease(input.Reason)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"package": pkg, "verification": verification(pkg.Verify())})
}
