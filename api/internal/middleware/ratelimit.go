package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	burstTokens  int       // max tokens (burst capacity)
	maxPerMin    int       // sustained tokens per minute
	tokens       float64   // current available tokens
	lastRefill   time.Time // last time tokens were refilled
	staleAt      time.Time // when this entry should be cleaned up
}

// refill adds tokens based on elapsed time. Refill rate = maxPerMin / 60 per second.
func (tb *tokenBucket) refill(now time.Time) {
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * (float64(tb.maxPerMin) / 60.0)
		if tb.tokens > float64(tb.burstTokens) {
			tb.tokens = float64(tb.burstTokens)
		}
		tb.lastRefill = now
	}
}

// allow returns true if a token is available and decrements the counter.
// If denied, returns the retry_after duration in seconds.
func (tb *tokenBucket) allow(now time.Time) (ok bool, retryAfter int) {
	tb.refill(now)
	if tb.tokens >= 1 {
		tb.tokens--
		tb.staleAt = now.Add(5 * time.Minute) // keep entry alive while active
		return true, 0
	}
	// Calculate how long until 1 token is available
	deficit := 1 - tb.tokens
	ratePerSec := float64(tb.maxPerMin) / 60.0
	retrySec := int(deficit / ratePerSec) + 1
	return false, retrySec
}

// limiter tracks rate limit state per IP address.
type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	burst    int
	maxPerMin int
}

// RateLimit returns a chi-compatible middleware that enforces per-IP rate limiting.
// burstPerSec is the maximum burst of requests allowed per second.
// maxPerMin is the sustained rate limit (tokens refilled per minute).
// /healthz is exempt from rate limiting.
func RateLimit(burstPerSec, maxPerMin int) func(http.Handler) http.Handler {
	l := &limiter{
		buckets:   make(map[string]*tokenBucket),
		burst:     burstPerSec,
		maxPerMin: maxPerMin,
	}

	// Background cleanup goroutine
	go l.cleanup()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Exempt /healthz from rate limiting
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			ip := clientIP(r)

			l.mu.Lock()
			tb, exists := l.buckets[ip]
			if !exists {
				tb = &tokenBucket{
					burstTokens: burstPerSec,
					maxPerMin:   maxPerMin,
					tokens:      float64(burstPerSec),
					lastRefill:  time.Now(),
					staleAt:     time.Now().Add(5 * time.Minute),
				}
				l.buckets[ip] = tb
			}
			ok, retryAfter := tb.allow(time.Now())
			l.mu.Unlock()

			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", time.Now().Add(time.Duration(retryAfter)*time.Second).Format(time.RFC1123))
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":      "rate limit exceeded",
					"retry_after": retryAfter,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (XFF may contain multiple: "ip1, ip2, ...")
		xffParts := strings.Split(xff, ",")
		if len(xffParts) > 0 {
			firstIP := strings.TrimSpace(xffParts[0])
			if host, _, err := net.SplitHostPort(firstIP); err == nil {
				return host
			}
			return firstIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cleanup removes stale bucket entries every 5 minutes.
func (l *limiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		l.mu.Lock()
		for ip, tb := range l.buckets {
			if now.After(tb.staleAt) {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}
