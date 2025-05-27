package admin

import (
	"encoding/json"
	"gradius/internal/metrics"
	"net/http"
	"sync"
)

type AdminServer struct {
	metrics *metrics.Metrics
	server  *http.Server
	mu      sync.RWMutex
}

func NewAdminServer(metrics *metrics.Metrics, addr string) *AdminServer {
	admin := &AdminServer{
		metrics: metrics,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", admin.handleMetrics)
	mux.HandleFunc("/health", admin.handleHealth)
	mux.HandleFunc("/status", admin.handleStatus)

	admin.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return admin
}

func (a *AdminServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := a.metrics.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (a *AdminServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := a.metrics.GetStats()
	status := map[string]interface{}{
		"metrics": stats,
		"health": map[string]string{
			"status": "ok",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (a *AdminServer) Start() error {
	return a.server.ListenAndServe()
}

func (a *AdminServer) Stop() error {
	return a.server.Close()
}
