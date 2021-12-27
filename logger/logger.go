package logger

import "go.uber.org/zap"

var log *zap.Logger

func init() {
	var err error

	log, err = zap.NewProduction(zap.AddCallerSkip(1))
	if err != nil {
		panic(err)
	}
}

func Info(messag string, fields ...zap.Field) {
	log.Info(messag, fields...)
}

func Debug(messag string, fields ...zap.Field) {
	log.Debug(messag, fields...)
}

func Error(messag string, fields ...zap.Field) {
	log.Error(messag, fields...)
}
