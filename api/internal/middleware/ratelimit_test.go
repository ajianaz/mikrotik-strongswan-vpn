package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	rl := RateLimit(5, 30) // burst=5, 30/min
	handler := rl(http.HandlerFunc(okHandler))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	rl := RateLimit(3, 10) // burst=3, 10/min
	handler := rl(http.HandlerFunc(okHandler))

	// Send burst + 2 more
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// These should be rate limited
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("overflow request %d: expected 429, got %d", i, rec.Code)
		}

		// Check Retry-After header is set
		if rec.Header().Get("Retry-After") == "" {
			t.Fatal("expected Retry-After header to be set")
		}

		// Check JSON error body
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error body: %v", err)
		}
		if body["error"] != "rate limit exceeded" {
			t.Fatalf("expected 'rate limit exceeded', got %v", body["error"])
		}
		if _, ok := body["retry_after"]; !ok {
			t.Fatal("expected retry_after field in response")
		}
	}
}

func TestRateLimit_HealthzExempt(t *testing.T) {
	rl := RateLimit(2, 5) // very small limit
	handler := rl(http.HandlerFunc(okHandler))

	// Send many requests to /healthz — all should pass
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("healthz request %d: expected 200 (exempt), got %d", i, rec.Code)
		}
	}
}

func TestRateLimit_PerIP(t *testing.T) {
	rl := RateLimit(2, 10) // burst=2
	handler := rl(http.HandlerFunc(okHandler))

	// IP 1 uses all tokens
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "1.1.1.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP1 request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// IP 1 is blocked
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("IP1 overflow: expected 429, got %d", rec.Code)
	}

	// IP 2 should still have its own full bucket
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "2.2.2.2:5678"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP2 request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestRateLimit_RetryAfterHeader(t *testing.T) {
	rl := RateLimit(1, 6) // burst=1, very low sustained rate
	handler := rl(http.HandlerFunc(okHandler))

	// Use the single token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Next should be rejected with Retry-After
	req = httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rec.Code)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header to be set on 429 response")
	}
	// Should be a date string (RFC1123)
	if len(retryAfter) < 10 {
		t.Fatalf("expected RFC1123 date in Retry-After, got %q", retryAfter)
	}
}
