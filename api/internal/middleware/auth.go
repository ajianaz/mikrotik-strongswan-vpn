package middleware

import (
	"net/http"
	"strings"
)

// APIKeyAuth returns a chi middleware that validates Bearer token authentication.
// Requests to paths NOT under /api/ are allowed through (public).
// Requests to /api/ paths require a valid Authorization header: "Bearer <api_key>".
// Returns 401 if missing or invalid.
func APIKeyAuth(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for non-API paths
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			if header == "" {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expected format: "Bearer <api_key>"
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" || parts[1] != apiKey {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
