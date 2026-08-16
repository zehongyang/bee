package config

import "testing"

// TestParseArgsIgnoresUnknownFlags 锁住这个包不再劫持全局 flag 解析：
// 业务程序自己的参数必须原样通过，不能像以前那样在 init() 里被 flag.Parse 判成非法参数直接退出。
func TestParseArgsIgnoresUnknownFlags(t *testing.T) {
	defer restoreGlobalConfig(globalConfig)

	parseArgs([]string{"-username", "boss", "-password", "s3cret", "-name", "老板"})

	if globalConfig.Debug {
		t.Fatalf("未传 -debug 时应为 false")
	}
	if globalConfig.Env != defaultEnvFile {
		t.Fatalf("未传 -env 时应回落到 %s，实际 %s", defaultEnvFile, globalConfig.Env)
	}
}

func TestParseArgs(t *testing.T) {
	defer restoreGlobalConfig(globalConfig)

	cases := []struct {
		name      string
		args      []string
		wantDebug bool
		wantEnv   string
	}{
		{"空参数", nil, false, defaultEnvFile},
		{"裸 debug", []string{"-debug"}, true, defaultEnvFile},
		{"双横线", []string{"--debug"}, true, defaultEnvFile},
		{"显式 false", []string{"-debug=false"}, false, defaultEnvFile},
		{"env 空格分隔", []string{"-env", "prod.env"}, false, "prod.env"},
		{"env 等号", []string{"--env=prod.env"}, false, "prod.env"},
		{"env 缺值", []string{"-env"}, false, defaultEnvFile},
		{"与业务参数混排", []string{"-username", "boss", "-debug", "-env=prod.env"}, true, "prod.env"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parseArgs(c.args)
			if globalConfig.Debug != c.wantDebug {
				t.Fatalf("debug 期望 %v，实际 %v", c.wantDebug, globalConfig.Debug)
			}
			if globalConfig.Env != c.wantEnv {
				t.Fatalf("env 期望 %s，实际 %s", c.wantEnv, globalConfig.Env)
			}
		})
	}
}

// restoreGlobalConfig 把包级状态还原，避免用例之间互相影响。
func restoreGlobalConfig(saved GlobalConfig) {
	globalConfig = saved
}
