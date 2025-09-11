package logger

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/zehongyang/bee/config"
	"os"
	"time"
)

var logger = newLogger()

type LoggerConfig struct {
	Logger struct {
		Level  string
		Writer string
	}
}

func newLogger() zerolog.Logger {
	var lc LoggerConfig
	err := config.Load(&lc)
	var tl = log.Logger.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Caller().Logger()
	if err != nil {
		tl.Fatal().Msg(err.Error())
	}
	level, err := zerolog.ParseLevel(lc.Logger.Level)
	if err != nil {
		tl.Fatal().Msg(err.Error())
	}
	if lc.Logger.Writer != "console" {
		fn, err := os.OpenFile(lc.Logger.Writer, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			tl.Fatal().Msg(err.Error())
		}
		tl = zerolog.New(fn).With().Timestamp().Caller().Logger()
	}
	zerolog.SetGlobalLevel(level)
	return tl
}

func Fatal() *zerolog.Event {
	return logger.Fatal()
}

func Info() *zerolog.Event {
	return logger.Info()
}

func Debug() *zerolog.Event {
	return logger.Debug()
}

func Warn() *zerolog.Event {
	return logger.Warn()
}

func Error() *zerolog.Event {
	return logger.Error()
}

func Trace() *zerolog.Event {
	return logger.Trace()
}

func Panic() *zerolog.Event {
	return logger.Panic()
}
