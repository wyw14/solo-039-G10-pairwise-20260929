package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/wyw14/solo-039/internal/service"
	"net/http"
)

type Server struct {
	runtime *service.Runtime
	plant   *service.Plant
	router  chi.Router
}

func NewServer() *Server { return NewServerWithData("data") }

// NewServerWithData builds a server whose durable journal and snapshot live in
// dataDir. It is mainly used by tests to isolate each server's files.
func NewServerWithData(dataDir string) *Server {
	plant := service.NewPlant(dataDir)
	_ = plant.Restore()
	s := &Server{runtime: service.NewRuntime("baseline"), plant: plant, router: chi.NewRouter()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.router }
