package config

import (
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envYamlFile     = "YamlFile"
	defaultYamlFile = "application.yml"
	defaultEnvFile  = "local.env"
)

type GlobalConfig struct {
	Debug    bool
	Env      string
	yamlFile string
}

var globalConfig GlobalConfig

var logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Caller().Logger()

func init() {
	parseArgs(os.Args[1:])
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

// parseArgs 从命令行里挑出框架自己关心的 -debug 和 -env，其余参数一律不管。
//
// 刻意不用标准库的 flag：init() 早于 main 执行，那时业务程序自己的参数还没注册，
// 在这里调用 flag.Parse() 会让任何带命令行参数的程序（比如 meeting_backend 的 adminctl）
// 因为"未定义的参数"直接退出。框架不该替业务程序决定命令行怎么解析，
// 所以这里只认这两个参数，认不出的全部跳过，留给调用方自己去 flag.Parse。
func parseArgs(args []string) {
	globalConfig.Debug = false
	globalConfig.Env = defaultEnvFile
	for i := 0; i < len(args); i++ {
		name, value, hasValue := splitArg(args[i])
		switch name {
		case "debug":
			if !hasValue {
				// 与 flag 包对布尔参数的约定一致：-debug 后面不跟值即为 true
				globalConfig.Debug = true
				continue
			}
			globalConfig.Debug, _ = strconv.ParseBool(value)
		case "env":
			if !hasValue {
				if i+1 >= len(args) {
					continue
				}
				i++
				value = args[i]
			}
			if value != "" {
				globalConfig.Env = value
			}
		}
	}
}

// splitArg 把 -name、--name、-name=value 拆成参数名和值；不是参数时返回空名字。
func splitArg(arg string) (name, value string, hasValue bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false
	}
	arg = strings.TrimLeft(arg, "-")
	if idx := strings.IndexByte(arg, '='); idx >= 0 {
		return arg[:idx], arg[idx+1:], true
	}
	return arg, "", false
}

func IsDebug() bool {
	return globalConfig.Debug
}

func Load(v any) error {
	return viper.Unmarshal(v)
}
