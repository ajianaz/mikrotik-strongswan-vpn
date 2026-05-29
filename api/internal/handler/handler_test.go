package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ajianaz/vpn-manager/internal/service"
)

// ---------------------------------------------------------------------------
// Mock service
// ---------------------------------------------------------------------------

type mockService struct {
	createFn func(context.Context, service.CreateTunnelInput) (*service.CreateTunnelResponse, error)
	listFn   func(context.Context, string) ([]service.Tunnel, error)
	getFn    func(context.Context, string) (*service.Tunnel, error)
	deleteFn func(context.Context, string) error
	rscFn    func(context.Context, string) (string, error)
	reloadFn func(context.Context) error
}

func (m *mockService) CreateTunnel(ctx context.Context, in service.CreateTunnelInput) (*service.CreateTunnelResponse, error) {
	return m.createFn(ctx, in)
}
func (m *mockService) ListTunnels(ctx context.Context, u string) ([]service.Tunnel, error) {
	return m.listFn(ctx, u)
}
func (m *mockService) GetTunnel(ctx context.Context, id string) (*service.Tunnel, error) {
	return m.getFn(ctx, id)
}
func (m *mockService) DeleteTunnel(ctx context.Context, id string) error {
	return m.deleteFn(ctx, id)
}
func (m *mockService) GetMikroTikRSC(ctx context.Context, id string) (string, error) {
	return m.rscFn(ctx, id)
}
func (m *mockService) ReloadAll(ctx context.Context) error {
	return m.reloadFn(ctx)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func setupRouter(svc service.TunnelService) *chi.Mux {
	r := chi.NewRouter()
	h := NewHandler(svc)
	r.Route("/api/v1", func(r chi.Router) {
		r.Mount("/tunnels", h.Routes())
		r.Post("/reload", h.ReloadAll)
	})
	return r
}

func decodeResponse(t *testing.T, body []byte) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// sampleTunnel returns a fixed Tunnel for tests.
func sampleTunnel() service.Tunnel {
	return service.Tunnel{
		ID:          "1",
		TunnelID:    "tun-abc123",
		Name:        "test-tunnel",
		PeerIP:      "10.10.10.2",
		LocalSubnet: "10.10.10.0/24",
		AuthType:    "eap",
		Username:    "test-tunnel-aabb1122",
		Status:      "active",
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func sampleCreateResponse() *service.CreateTunnelResponse {
	t := sampleTunnel()
	return &service.CreateTunnelResponse{
		Tunnel:   t,
		Password: "secret123",
	}
}

// ---------------------------------------------------------------------------
// CreateTunnel tests (POST /api/v1/tunnels)
// ---------------------------------------------------------------------------

func TestCreateTunnel_ValidInput(t *testing.T) {
	svc := &mockService{
		createFn: func(_ context.Context, in service.CreateTunnelInput) (*service.CreateTunnelResponse, error) {
			return sampleCreateResponse(), nil
		},
	}
	r := setupRouter(svc)

	body := mustJSON(t, service.CreateTunnelInput{Name: "test-tunnel"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map")
	}
	if data["tunnel_id"] != "tun-abc123" {
		t.Fatalf("expected tunnel_id tun-abc123, got %v", data["tunnel_id"])
	}
}

func TestCreateTunnel_EmptyBody(t *testing.T) {
	svc := &mockService{}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "invalid JSON body" {
		t.Fatalf("expected 'invalid JSON body', got %q", resp.Error)
	}
}

func TestCreateTunnel_InvalidJSON(t *testing.T) {
	svc := &mockService{}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "invalid JSON body" {
		t.Fatalf("expected 'invalid JSON body', got %q", resp.Error)
	}
}

func TestCreateTunnel_MissingName(t *testing.T) {
	svc := &mockService{}
	r := setupRouter(svc)

	body := mustJSON(t, map[string]string{"local_subnet": "10.0.0.0/24"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "name is required" {
		t.Fatalf("expected 'name is required', got %q", resp.Error)
	}
}

func TestCreateTunnel_ErrInvalidName(t *testing.T) {
	svc := &mockService{
		createFn: func(_ context.Context, _ service.CreateTunnelInput) (*service.CreateTunnelResponse, error) {
			return nil, service.ErrInvalidName
		},
	}
	r := setupRouter(svc)

	body := mustJSON(t, service.CreateTunnelInput{Name: "bad/name"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateTunnel_ErrNoAvailableIP(t *testing.T) {
	svc := &mockService{
		createFn: func(_ context.Context, _ service.CreateTunnelInput) (*service.CreateTunnelResponse, error) {
			return nil, service.ErrNoAvailableIP
		},
	}
	r := setupRouter(svc)

	body := mustJSON(t, service.CreateTunnelInput{Name: "test-tunnel"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if !strings.Contains(resp.Error, "no available IP") {
		t.Fatalf("expected 'no available IP' in error, got %q", resp.Error)
	}
}

func TestCreateTunnel_InternalError(t *testing.T) {
	svc := &mockService{
		createFn: func(_ context.Context, _ service.CreateTunnelInput) (*service.CreateTunnelResponse, error) {
			return nil, errors.New("db connection lost")
		},
	}
	r := setupRouter(svc)

	body := mustJSON(t, service.CreateTunnelInput{Name: "test-tunnel"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}

func TestCreateTunnel_BodyTooLarge(t *testing.T) {
	svc := &mockService{}
	r := setupRouter(svc)

	// Create a body larger than 1MB — MaxBytesReader will reject it
	bigBody := bytes.Repeat([]byte("x"), 2<<20)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	// The handler calls writeError which maps the MaxBytesReader error to 500
	// since it doesn't match any known error types in writeError.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error == "" {
		t.Fatal("expected an error message")
	}
}

// ---------------------------------------------------------------------------
// ListTunnels tests (GET /api/v1/tunnels)
// ---------------------------------------------------------------------------

func TestListTunnels_ReturnsTunnels(t *testing.T) {
	tunnels := []service.Tunnel{sampleTunnel()}
	svc := &mockService{
		listFn: func(_ context.Context, _ string) ([]service.Tunnel, error) {
			return tunnels, nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.([]any)
	if !ok {
		t.Fatal("expected data to be array")
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(data))
	}
}

func TestListTunnels_EmptyList(t *testing.T) {
	svc := &mockService{
		listFn: func(_ context.Context, _ string) ([]service.Tunnel, error) {
			return nil, nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.([]any)
	if !ok {
		t.Fatal("expected data to be array")
	}
	if len(data) != 0 {
		t.Fatalf("expected 0 tunnels, got %d", len(data))
	}
}

func TestListTunnels_ServiceError(t *testing.T) {
	svc := &mockService{
		listFn: func(_ context.Context, _ string) ([]service.Tunnel, error) {
			return nil, errors.New("db error")
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}

func TestListTunnels_WithUsernameFilter(t *testing.T) {
	var receivedUsername string
	svc := &mockService{
		listFn: func(_ context.Context, username string) ([]service.Tunnel, error) {
			receivedUsername = username
			return nil, nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels?username=alice", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedUsername != "alice" {
		t.Fatalf("expected username 'alice', got %q", receivedUsername)
	}
}

// ---------------------------------------------------------------------------
// GetTunnel tests (GET /api/v1/tunnels/{tunnelID})
// ---------------------------------------------------------------------------

func TestGetTunnel_Valid(t *testing.T) {
	svc := &mockService{
		getFn: func(_ context.Context, _ string) (*service.Tunnel, error) {
			t := sampleTunnel()
			return &t, nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map")
	}
	if data["tunnel_id"] != "tun-abc123" {
		t.Fatalf("expected tunnel_id tun-abc123, got %v", data["tunnel_id"])
	}
}

func TestGetTunnel_NotFound(t *testing.T) {
	svc := &mockService{
		getFn: func(_ context.Context, _ string) (*service.Tunnel, error) {
			return nil, &service.NotFoundError{TunnelID: "tun-abc123"}
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if !strings.Contains(resp.Error, "tun-abc123") {
		t.Fatalf("expected error to contain tunnel ID, got %q", resp.Error)
	}
}

func TestGetTunnel_ServiceError(t *testing.T) {
	svc := &mockService{
		getFn: func(_ context.Context, _ string) (*service.Tunnel, error) {
			return nil, errors.New("db error")
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}

// ---------------------------------------------------------------------------
// DeleteTunnel tests (DELETE /api/v1/tunnels/{tunnelID})
// ---------------------------------------------------------------------------

func TestDeleteTunnel_Success(t *testing.T) {
	svc := &mockService{
		deleteFn: func(_ context.Context, _ string) error {
			return nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map")
	}
	if data["message"] != "deleted" {
		t.Fatalf("expected 'deleted', got %v", data["message"])
	}
}

func TestDeleteTunnel_NotFound(t *testing.T) {
	svc := &mockService{
		deleteFn: func(_ context.Context, _ string) error {
			return &service.NotFoundError{TunnelID: "tun-abc123"}
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteTunnel_ServiceError(t *testing.T) {
	svc := &mockService{
		deleteFn: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tunnels/tun-abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}

// ---------------------------------------------------------------------------
// GetMikroTikRSC tests (GET /api/v1/tunnels/{tunnelID}/rsc)
// ---------------------------------------------------------------------------

func TestGetMikroTikRSC_Success(t *testing.T) {
	svc := &mockService{
		rscFn: func(_ context.Context, _ string) (string, error) {
			return "/ip address add address=10.10.10.2/24 interface=ether1\n/ip ipsec peer add name=tun-abc123", nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123/rsc", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Fatalf("expected Content-Type text/plain, got %q", ct)
	}
	body := strings.TrimSpace(rec.Body.String())
	if !strings.Contains(body, "/ip address") {
		t.Fatalf("expected script body, got %q", body)
	}
}

func TestGetMikroTikRSC_NotFound(t *testing.T) {
	svc := &mockService{
		rscFn: func(_ context.Context, _ string) (string, error) {
			return "", &service.NotFoundError{TunnelID: "tun-abc123"}
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123/rsc", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetMikroTikRSC_ServiceError(t *testing.T) {
	svc := &mockService{
		rscFn: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("decrypt failed")
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels/tun-abc123/rsc", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}

// ---------------------------------------------------------------------------
// ReloadAll tests (POST /api/v1/reload)
// ---------------------------------------------------------------------------

func TestReloadAll_Success(t *testing.T) {
	svc := &mockService{
		reloadFn: func(_ context.Context) error {
			return nil
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map")
	}
	if data["message"] != "reloaded" {
		t.Fatalf("expected 'reloaded', got %v", data["message"])
	}
}

func TestReloadAll_ServiceError(t *testing.T) {
	svc := &mockService{
		reloadFn: func(_ context.Context) error {
			return errors.New("swanctl reload failed")
		},
	}
	r := setupRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec.Body.Bytes())
	if resp.Error != "internal server error" {
		t.Fatalf("expected 'internal server error', got %q", resp.Error)
	}
}
