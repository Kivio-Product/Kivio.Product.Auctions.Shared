package tools

import (
	"net/http"
	"time"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

func RequestLogger(loggerRepo domainLogging.LoggerRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()
			
			logger := loggerRepo.GetLogger().WithFields(domainLogging.Fields{
				"component": "http_middleware",
			})
			
			logger.Info(ctx, "HTTP request started", domainLogging.Fields{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_addr": r.RemoteAddr,
				"user_agent": r.Header.Get("User-Agent"),
			})
			
			next.ServeHTTP(w, r)
			
			duration := time.Since(start)
			logger.Info(ctx, "HTTP request completed", domainLogging.Fields{
				"method":      r.Method,
				"path":        r.URL.Path,
				"duration_ms": duration.Milliseconds(),
			})
		})
	}
}
