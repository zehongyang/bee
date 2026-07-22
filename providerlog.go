package bee

import (
	"time"

	"github.com/zehongyang/bee/logger"
)

// LogProviderCall 统一记录一次第三方 Provider（LLM、支付、短信等）调用的耗时和结果，不记录请求/响应正文，
// 避免每个业务模块各自实现一套调用日志，也避免不小心把敏感内容打进日志。
// provider 是第三方服务名，例如 "deepseek"、"wechatpay"；action 是这次调用做的事情，例如 "chat_completion"；
// start 是调用开始时间；err 为 nil 表示调用成功，否则记录失败原因。
func LogProviderCall(provider, action string, start time.Time, err error) {
	event := logger.Info()
	if err != nil {
		event = logger.Error().Err(err)
	}
	event.
		Str("provider", provider).
		Str("action", action).
		Int64("duration_ms", time.Since(start).Milliseconds()).
		Msg("provider call")
}
