package logging

import (
	"fmt"
	"sync"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/config"
)

var (
	loggerInstance     domainLogging.LoggerRepository
	loggerInstanceOnce sync.Once
)

type LoggingInitializer struct {
	config *config.LoggingConfig
}

func NewLoggingInitializer() (*LoggingInitializer, error) {
	cfg, err := config.LoadLoggingConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load logging configuration: %w", err)
	}

	return &LoggingInitializer{
		config: cfg,
	}, nil
}

func (li *LoggingInitializer) InitializeLogger() (domainLogging.LoggerRepository, error) {
	var initErr error

	loggerInstanceOnce.Do(func() {
		domainConfig := li.config.ToDomainConfig()

		lokiLogger, err := NewLokiLogger(domainConfig)
		if err != nil {
			initErr = fmt.Errorf("failed to create loki logger: %w", err)
			return
		}

		loggerInstance = NewLoggerRepository(lokiLogger)
	})

	if initErr != nil {
		return nil, initErr
	}

	return loggerInstance, nil
}

func GetLoggerRepository() domainLogging.LoggerRepository {
	if loggerInstance == nil {
		initializer, err := NewLoggingInitializer()
		if err != nil {
			panic(fmt.Sprintf("Failed to initialize logging: %v", err))
		}

		repo, err := initializer.InitializeLogger()
		if err != nil {
			panic(fmt.Sprintf("Failed to initialize logger repository: %v", err))
		}

		return repo
	}

	return loggerInstance
}

func (li *LoggingInitializer) GetConfig() *config.LoggingConfig {
	return li.config
}
