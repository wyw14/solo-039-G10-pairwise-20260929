package api

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/wyw14/solo-039/internal/release"
	"net/http"
)

type releaseRequest struct {
	Revision string `json:"revision"`
	Reason   string `json:"reason"`
}

func (s *Server) currentRevision() string { return s.plant.Campaign.Snapshot().Revision.String() }

// packageView renders a frozen package alongside a fresh verification, so a
// customer can see both the original conclusion and whether it still checks
// out against the embedded evidence.
func packageView(pkg release.Package, verifyErr error) map[string]any {
	missing := make([]string, 0, len(pkg.MissingSections()))
	for _, section := range pkg.MissingSections() {
		missing = append(missing, string(section))
	}
	verification := map[string]any{"ok": verifyErr == nil}
	if verifyErr != nil {
		verification["error"] = verifyErr.Error()
	}
	return map[string]any{
		"package":      pkg,
		"missing":      missing,
		"verifies":     verification["ok"],
		"verification": verification,
	}
}

func (s *Server) decodeReleaseRequest(w http.ResponseWriter, r *http.Request) (releaseRequest, bool) {
	var input releaseRequest
	if r.Body != nil && r.ContentLength != 0 {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return input, false
		}
	}
	if input.Revision == "" {
		input.Revision = s.currentRevision()
	}
	return input, true
}

func (s *Server) issueRelease(w http.ResponseWriter, r *http.Request) {
	input, ok := s.decodeReleaseRequest(w, r)
	if !ok {
		return
	}
	pkg, err := s.plant.IssueRelease(input.Revision)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, packageView(pkg, pkg.Verify()))
}

func (s *Server) supplementRelease(w http.ResponseWriter, r *http.Request) {
	input, ok := s.decodeReleaseRequest(w, r)
	if !ok {
		return
	}
	pkg, err := s.plant.SupplementRelease(input.Revision)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, packageView(pkg, pkg.Verify()))
}

func (s *Server) revokeRelease(w http.ResponseWriter, r *http.Request) {
	input, ok := s.decodeReleaseRequest(w, r)
	if !ok {
		return
	}
	if input.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revocation reason is required"})
		return
	}
	pkg, err := s.plant.RevokeRelease(input.Revision, input.Reason)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, packageView(pkg, pkg.Verify()))
}

func (s *Server) releases(w http.ResponseWriter, r *http.Request) {
	revision := r.URL.Query().Get("revision")
	if revision == "" {
		revisions := s.plant.Releases.Revisions()
		latest := make([]any, 0, len(revisions))
		for _, rev := range revisions {
			pkg, err := s.plant.Releases.Latest(rev)
			if err == nil {
				latest = append(latest, packageView(pkg, pkg.Verify()))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions, "latest": latest})
		return
	}
	history, err := s.plant.ReleaseHistory(revision)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	views := make([]any, 0, len(history))
	for _, pkg := range history {
		views = append(views, packageView(pkg, pkg.Verify()))
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": revision, "versions": views})
}

func (s *Server) releasePackage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid package id"})
		return
	}
	pkg, err := s.plant.ReleasePackageVersion(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, packageView(pkg, pkg.Verify()))
}
