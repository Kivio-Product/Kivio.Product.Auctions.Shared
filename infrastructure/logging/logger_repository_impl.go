package logging

import (
	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type LoggerRepositoryImpl struct {
	logger domainLogging.Logger
}

func NewLoggerRepository(logger domainLogging.Logger) domainLogging.LoggerRepository {
	return &LoggerRepositoryImpl{
		logger: logger,
	}
}

func (r *LoggerRepositoryImpl) GetLogger() domainLogging.Logger {
	return r.logger
}

func (r *LoggerRepositoryImpl) GetLoggerWithFields(fields domainLogging.Fields) domainLogging.Logger {
	return r.logger.WithFields(fields)
}

func (r *LoggerRepositoryImpl) CreateChildLogger(fields domainLogging.Fields) domainLogging.Logger {
	return r.logger.WithFields(fields)
}