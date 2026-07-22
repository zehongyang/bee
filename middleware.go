// 本文件的中间件依赖 IContext.Next() 真正串联调用链，目前只有 HttpServer.Use 支持这种链式调用，
// WebSocket/TCP 的 Next() 是空实现，因此这些中间件只应该注册到 HttpServer 上。
package bee

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
)

// RequestIDHeader 是请求链路标识在 HTTP 头里使用的字段名。
const RequestIDHeader = "X-Request-Id"

// requestIDContextKey 是 request_id 存入 IContext.Set/Get 时使用的 key，业务代码不应该直接使用这个 key。
const requestIDContextKey = "bee:request_id"

// RequestID 返回一个中间件：优先复用调用方传入的 X-Request-Id，没有则生成一个新的，
// 写回响应头并存入 ctx，供后续中间件（AccessLog、Recovery）和业务 handler 组装统一响应体时使用。
func RequestID() Handler {
	return func(ctx IContext) {
		id := ctx.GetHeader(RequestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		ctx.Set(requestIDContextKey, id)
		ctx.SetHeader(RequestIDHeader, id)
		ctx.Next()
	}
}

// GetRequestID 取出当前请求的 request_id，取不到时返回空字符串（说明没有注册 RequestID 中间件）。
func GetRequestID(ctx IContext) string {
	v, ok := ctx.Get(requestIDContextKey)
	if !ok {
		return ""
	}
	id, _ := v.(string)
	return id
}

// newRequestID 生成一个 16 字节随机数的十六进制字符串，作为不会重复的请求标识。
func newRequestID() string {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// AccessLog 返回一个中间件：按结构化字段记录每次请求的方法、路径、状态码和耗时，不记录请求/响应正文。
func AccessLog() Handler {
	return func(ctx IContext) {
		start := time.Now()
		ctx.Next()
		logger.Info().
			Str("request_id", GetRequestID(ctx)).
			Str("method", ctx.GetMethod()).
			Str("path", ctx.GetPath()).
			Int("status", ctx.GetStatus()).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Msg("access")
	}
}

// Recovery 返回一个中间件：捕获后续中间件和 handler 里的 panic，记录堆栈后返回统一的内部错误响应，
// 避免单个请求的 panic 打挂整个进程。必须注册在其它中间件之前，才能兜住它们的 panic。
func Recovery() Handler {
	return func(ctx IContext) {
		defer func() {
			if r := recover(); r != nil {
				stack := utils.Stack(3)
				logger.Error().
					Str("request_id", GetRequestID(ctx)).
					Any("panic", r).
					Str("stack", string(stack)).
					Msg("panic recovered")
				RespondError(ctx, "internal_error", "服务内部错误", true)
				// 必须显式 Abort，否则 gin 的调用链循环不知道发生过 panic，会继续执行后面的 handler。
				ctx.AbortWithStatus(200)
			}
		}()
		ctx.Next()
	}
}
