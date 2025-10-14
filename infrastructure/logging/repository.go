package logging

import (
	"fmt"
	"sync"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type LoggerRepository struct {
	logger logging.Logger
	config *LokiConfig
	mu     sync.RWMutex
}

var (
	instance *LoggerRepository
	once     sync.Once
)

func GetLoggerRepository() *LoggerRepository {
	once.Do(func() {
		config := GetLokiConfigFromEnv()

		var logger logging.Logger
		var err error

		if config.IsValid() {
			logger, err = NewLokiLogger(config)
			if err != nil {
				logger = NewConsoleLogger(config.ServiceName, config.LogLevel)
				fmt.Printf("Warning: Failed to initialize Loki logger, using console fallback: %v\n", err)
			}
		} else {
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

func (r *LoggerRepository) GetLogger() logging.Logger {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.logger
}

func (r *LoggerRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return nil
}

func (r *LoggerRepository) SetLogger(logger logging.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logger = logger
}
