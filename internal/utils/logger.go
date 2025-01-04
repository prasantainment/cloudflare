package utils

import (
	"go.uber.org/zap"
)

// InitLogger initializes the zap logger.
func InitLogger(cfg *zap.Config) *zap.SugaredLogger {
	logger, _ := zap.NewProduction()
	if cfg.Encoding == "debug" {
		logger, _ = zap.NewDevelopment()
	}
	return logger.Sugar()
}
