package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyAuth(t *testing.T) {
	apiKey := "test-secret-key"

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := APIKeyAuth(apiKey)(nextHandler)

	tests := []struct {
		name       string
		method     string
		path       string
		authHeader string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid Bearer token on API path",
			method:     "GET",
			path:       "/api/v1/tunnels",
			authHeader: "Bearer test-secret-key",
			wantStatus: http.StatusOK,
			wantBody:   "OK",
		},
		{
			name:       "missing Authorization header on API path",
			method:     "GET",
			path:       "/api/v1/tunnels",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
		{
			name:       "wrong token",
			method:     "GET",
			path:       "/api/v1/tunnels",
			authHeader: "Bearer wrong-key",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
		{
			name:       "Basic scheme instead of Bearer",
			method:     "GET",
			path:       "/api/v1/tunnels",
			authHeader: "Basic dGVzdDp0ZXN0",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
		{
			name:       "empty Bearer token",
			method:     "GET",
			path:       "/api/v1/tunnels",
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
		{
			name:       "non-API path skips auth",
			method:     "GET",
			path:       "/healthz",
			authHeader: "",
			wantStatus: http.StatusOK,
			wantBody:   "OK",
		},
		{
			name:       "non-API path ignores wrong auth",
			method:     "GET",
			path:       "/healthz",
			authHeader: "Bearer wrong-key",
			wantStatus: http.StatusOK,
			wantBody:   "OK",
		},
		{
			name:       "API path requires auth",
			method:     "POST",
			path:       "/api/v1/tunnels",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestAPIKeyAuth_TimingSafeComparison(t *testing.T) {
	// Ensure the middleware uses constant-time comparison.
	// This is implicit from the code using subtle.ConstantTimeCompare,
	// but we verify that a token differing only in the last character is still rejected.
	apiKey := "test-secret-key"
	handler := APIKeyAuth(apiKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Token that differs by one character at the end
	req := httptest.NewRequest("GET", "/api/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer test-secret-kef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
