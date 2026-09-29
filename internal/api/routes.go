package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) routes() {
	s.router.MethodNotAllowed(methodNotAllowed)
	s.router.Get("/healthz", s.health)
	s.router.Get("/api/operations", s.operations)
	s.router.Get("/api/equipment", s.equipment)
	s.router.Get("/api/interlocks", s.interlocks)
	s.router.Get("/api/incidents", s.incidents)
	s.router.Post("/api/campaign/start", s.start)
	s.router.Post("/api/campaign/transition", s.transition)
	s.router.Post("/api/analyzer/samples", s.sample)
	s.router.Post("/api/analyzer/calibrate", s.calibrate)
	s.router.Post("/api/products/route", s.routeProduct)
	s.router.Post("/api/reflux/leases", s.lease)
	s.router.Post("/api/shutdown", s.shutdown)
	s.router.Get("/api/snapshot", s.snapshot)
	s.router.Get("/api/evidence", s.evidence)
	s.router.Get("/api/recovery", s.recovery)
	s.router.Get("/api/profile", s.profile)
	s.router.Get("/api/metrics", s.metrics)

	s.router.Route("/api/release", func(r chi.Router) {
		r.Get("/packages", s.releasePackages)
		r.Post("/packages", s.assembleReleasePackage)
		r.Get("/packages/latest", s.latestReleasePackage)
		r.Get("/packages/versions/{version}", s.releasePackageByVersion)
		r.Get("/packages/{id}", s.releasePackageByID)
		r.Post("/resupplement", s.resupplementRelease)
		r.Post("/revoke", s.revokeRelease)
	})
}

func (s *Server) interlocks(w http.ResponseWriter, r *http.Request) {
	status := s.plant.Status()
	columnState := status["column"]
	writeJSON(w, http.StatusOK, map[string]any{"ready": s.plant.Snapshot().Column.Pressure < 2, "column": columnState})
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.plant.Incidents.List(false)})
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	grade := r.URL.Query().Get("grade")
	if grade == "" {
		grade = "baseline"
	}
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "primary"
	}
	if _, err := s.plant.Start(r.Context(), grade, source); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}
