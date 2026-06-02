// Package handler provides HTTP handlers for the VPN tunnel REST API.
package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ajianaz/vpn-manager/internal/service"
)

// errInternalServer is the generic error message returned for unclassified errors.
const errInternalServer = "internal server error"

// Response is the JSON response envelope for all API endpoints.
type Response struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// writeJSON marshals data as {"data": data} and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(Response{Data: data}); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// writeError writes {"error": message} with an appropriate status code.
//   - service.NotFoundError → 404
//   - service.ErrNoAvailableIP (wrapped) → 503
//   - otherwise → 500
func writeError(w http.ResponseWriter, err error) {
	var notFound *service.NotFoundError
	if errors.As(err, &notFound) {
		writeErrorJSON(w, http.StatusNotFound, err.Error())
		return
	}

	if errors.Is(err, service.ErrNoAvailableIP) {
		writeErrorJSON(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	if errors.Is(err, service.ErrInvalidName) {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Error("internal error", "error", err)
	writeErrorJSON(w, http.StatusInternalServerError, errInternalServer)
}

// writeErrorJSON writes a JSON error response with the given status code.
func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Response{Error: message})
}

// Handler holds the service dependency for HTTP handlers.
type Handler struct {
	svc service.TunnelService
}

// NewHandler creates a new Handler with the given service.
func NewHandler(svc service.TunnelService) *Handler {
	return &Handler{svc: svc}
}

// Routes returns a chi.Router with all tunnel CRUD endpoints.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/", h.CreateTunnel)
	r.Get("/", h.ListTunnels)
	r.Get("/{tunnelID}", h.GetTunnel)
	r.Delete("/{tunnelID}", h.DeleteTunnel)
	r.Get("/{tunnelID}/rsc", h.GetMikroTikRSC)
	// NOTE: POST /reload is registered at /api/v1/reload in main.go, not here (#56)
	return r
}

// CreateTunnel handles POST / — creates a new VPN tunnel.
func (h *Handler) CreateTunnel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, err)
		return
	}
	defer r.Body.Close()

	var input service.CreateTunnelInput
	if unmarshalErr := json.Unmarshal(body, &input); unmarshalErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Response{Error: "invalid JSON body"})
		return
	}

	if input.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Response{Error: "name is required"})
		return
	}

	resp, err := h.svc.CreateTunnel(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ListTunnels handles GET / — returns all tunnels, never null.
// Supports optional ?username= filter.
func (h *Handler) ListTunnels(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	tunnels, err := h.svc.ListTunnels(r.Context(), username)
	if err != nil {
		writeError(w, err)
		return
	}

	if tunnels == nil {
		tunnels = []service.Tunnel{}
	}

	writeJSON(w, http.StatusOK, tunnels)
}

// GetTunnel handles GET /{tunnelID} — returns a single tunnel.
func (h *Handler) GetTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := chi.URLParam(r, "tunnelID")

	tunnel, err := h.svc.GetTunnel(r.Context(), tunnelID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, tunnel)
}

// DeleteTunnel handles DELETE /{tunnelID} — deletes a tunnel.
func (h *Handler) DeleteTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := chi.URLParam(r, "tunnelID")

	if err := h.svc.DeleteTunnel(r.Context(), tunnelID); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

// GetMikroTikRSC handles GET /{tunnelID}/rsc — returns a RouterOS script as plain text.
func (h *Handler) GetMikroTikRSC(w http.ResponseWriter, r *http.Request) {
	tunnelID := chi.URLParam(r, "tunnelID")

	script, err := h.svc.GetMikroTikRSC(r.Context(), tunnelID)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// ReloadAll handles POST /reload — reloads strongSwan configuration.
func (h *Handler) ReloadAll(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.ReloadAll(r.Context()); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "reloaded"})
}
