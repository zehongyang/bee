package authtoken

import (
	"strings"

	"github.com/zehongyang/bee"
)

// bearerPrefix 是 Authorization 请求头里 Bearer token 的前缀。
const bearerPrefix = "Bearer "

// Middleware 返回一个 bee.Handler，从请求头 Authorization 里解析 token 并校验登录态。
// 校验通过后把 uid 写入 ctx 的 AccountInfo 并放行；校验失败则返回统一的未登录错误并终止后续处理。
// 只能注册到 bee.HttpServer 上（依赖 Next() 真正串联调用链）。
func Middleware(rdsName string) bee.Handler {
	return func(ctx bee.IContext) {
		token := extractToken(ctx.GetHeader("Authorization"))
		uid, err := Verify(rdsName, token)
		if err != nil {
			bee.RespondError(ctx, "unauthenticated", "登录状态已失效，请重新登录", false)
			// 必须显式 Abort，否则不调用 ctx.Next() 并不能阻止 gin 继续执行后面的 handler。
			ctx.AbortWithStatus(200)
			return
		}
		ctx.SetAccount(bee.AccountInfo{Uid: uid})
		ctx.Next()
	}
}

// extractToken 从 Authorization 请求头原始值中取出 Bearer token，兼容没有 Bearer 前缀的传法。
func extractToken(header string) string {
	if header == "" {
		return ""
	}
	if strings.HasPrefix(header, bearerPrefix) {
		return strings.TrimPrefix(header, bearerPrefix)
	}
	return header
}
