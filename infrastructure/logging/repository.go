package logging

import (
	"fmt"
	"sync"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// LoggerRepository implements domain logging.LoggerRepository
type LoggerRepository struct {
	logger logging.Logger
	config *LokiConfig
	mu     sync.RWMutex
}

var (
	instance *LoggerRepository
	once     sync.Once
)

// GetLoggerRepository returns a singleton instance of LoggerRepository
func GetLoggerRepository() *LoggerRepository {
	once.Do(func() {
		config := GetLokiConfigFromEnv()

		var logger logging.Logger
		var err error

		if config.IsValid() {
			logger, err = NewLokiLogger(config)
			if err != nil {
				// Fallback to console logger if Loki fails
				logger = NewConsoleLogger(config.ServiceName, config.LogLevel)
				fmt.Printf("Warning: Failed to initialize Loki logger, using console fallback: %v\n", err)
			}
		} else {
			// Use console logger if Loki is not configured
			logger = NewConsoleLogger(config.ServiceName, config.LogLevel)
			if config.Enabled {
				fmt.Println("Warning: Loki is enabled but configuration is invalid, using console fallback")
			}
		}

		instance = &LoggerRepository{
			logger: logger,
			config: config,
		}
	})
	return instance
}

// GetLogger implements logging.LoggerRepository.GetLogger
func (r *LoggerRepository) GetLogger() logging.Logger {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.logger
}

// Close implements logging.LoggerRepository.Close
func (r *LoggerRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// If it's a LokiLogger, we might want to flush pending logs
	// For now, we don't have a close method on the Loki client
	return nil
}

// SetLogger allows overriding the logger (useful for testing)
func (r *LoggerRepository) SetLogger(logger logging.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logger = logger
}