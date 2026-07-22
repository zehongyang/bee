package bee

import (
	"errors"
	"testing"
	"time"
)

// TestLogProviderCallDoesNotPanic 只做冒烟测试：确保成功和失败两种场景下调用都不会 panic。
// zerolog 全局 logger 写到 stderr，没有暴露可测试的输出重定向接口，这里不校验具体日志内容。
func TestLogProviderCallDoesNotPanic(t *testing.T) {
	LogProviderCall("deepseek", "chat_completion", time.Now(), nil)
	LogProviderCall("wechatpay", "create_order", time.Now(), errors.New("boom"))
}
