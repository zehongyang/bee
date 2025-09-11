package config

import (
	"flag"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"os"
	"testing"
	"time"
)

const (
	envYamlFile     = "YamlFile"
	defaultYamlFile = "application.yml"
)

type GlobalConfig struct {
	Debug    bool
	Env      string
	yamlFile string
}

var globalConfig GlobalConfig

var logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Caller().Logger()

func init() {
	testing.Init()
	flag.BoolVar(&globalConfig.Debug, "debug", false, "debug mode")
	flag.StringVar(&globalConfig.Env, "env", "local.env", "environment file")
	flag.Parse()
	_ = godotenv.Load(globalConfig.Env)
	globalConfig.yamlFile = defaultYamlFile
	yamlFile := os.Getenv(envYamlFile)
	if yamlFile != "" {
		globalConfig.yamlFile = yamlFile
	}
	viper.SetConfigFile(globalConfig.yamlFile)
	err := viper.ReadInConfig()
	if err != nil {
		logger.Fatal().Msg(err.Error())
	}
}

func IsDebug() bool {
	return globalConfig.Debug
}

func Load(v any) error {
	return viper.Unmarshal(v)
}
