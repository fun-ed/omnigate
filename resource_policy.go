package main

import (
	"errors"
	"net/http"
)

// limitRequestBody caps bytes read from each application request body. A known
// oversized Content-Length is rejected before next runs. Unknown-length bodies
// are capped as they are consumed, so up to max bytes may already have reached
// a downstream handler; this is not an atomic upload and must not be retried.
func limitRequestBody(max int64, next http.Handler) http.Handler {
	if max == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > max {
			if r.Body != nil {
				_ = r.Body.Close()
			}
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}

		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		limitedBody := http.MaxBytesReader(w, r.Body, max)
		r.Body = limitedBody
		defer func() { _ = limitedBody.Close() }()
		next.ServeHTTP(w, r)
	})
}

// proxyErrorStatus maps client request-body limit errors to 413; other proxy
// failures retain the existing Bad Gateway behavior.
func proxyErrorStatus(err error) int {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadGateway
}
