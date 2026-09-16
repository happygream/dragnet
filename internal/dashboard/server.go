package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/happygream/dragnet/internal/monitor"
)

// Server exposes the monitor state over HTTP: an embedded dashboard page plus
// a small JSON API the page polls.
type Server struct {
	mon    *monitor.Monitor
	store  *monitor.Store
	listen string
	srv    *http.Server
}

// New builds a dashboard server bound to listen (e.g. "127.0.0.1:8787").
func New(mon *monitor.Monitor, store *monitor.Store, listen string) *Server {
	return &Server{mon: mon, store: store, listen: listen}
}

// ListenAndServe starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/changes", s.handleChanges)

	s.srv = &http.Server{
		Addr:              s.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

type statePayload struct {
	Target   string          `json:"target"`
	Interval string          `json:"interval"`
	LastScan string          `json:"last_scan"`
	Scanning bool            `json:"scanning"`
	Runs     int             `json:"runs"`
	HostsUp  int             `json:"hosts_up"`
	Hosts    json.RawMessage `json:"hosts"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	hosts, last, scanning, runs := s.mon.Snapshot()
	up := 0
	for _, h := range hosts {
		if h.Alive {
			up++
		}
	}
	blob, _ := json.Marshal(hosts)
	lastStr := ""
	if !last.IsZero() {
		lastStr = last.Format(time.RFC3339)
	}
	writeJSON(w, statePayload{
		Target:   s.mon.Target(),
		Interval: s.mon.Interval().String(),
		LastScan: lastStr,
		Scanning: scanning,
		Runs:     runs,
		HostsUp:  up,
		Hosts:    blob,
	})
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	changes, err := s.store.RecentChanges(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, changes)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("encode: %v", err), http.StatusInternalServerError)
	}
}
