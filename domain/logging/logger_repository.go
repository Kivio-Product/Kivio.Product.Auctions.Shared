package logging

type LoggerRepository interface {
	GetLogger() Logger
	GetLoggerWithFields(fields Fields) Logger
	CreateChildLogger(fields Fields) Logger
}