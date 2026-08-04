package authtoken

import (
	"net/http"
	"strings"

	"github.com/zehongyang/bee"
)

// bearerPrefix 是 Authorization 请求头里 Bearer token 的前缀。
const bearerPrefix = "Bearer "

// UnauthenticatedCode / UnauthenticatedMessage 是登录态校验失败时写回的错误码和文案。
//
// 默认用 HTTP 401 作为错误码，业务项目通常有自己的错误码枚举，可以在启动阶段覆盖成对应取值，
// 让中间件和自家 handler 返回的错误码来自同一张表——否则客户端会收到两套编号，
// 没法用统一逻辑判断"是不是要跳登录页"。
//
// 只应该在进程启动、注册路由之前赋值，运行期不要改。
var (
	UnauthenticatedCode    = http.StatusUnauthorized
	UnauthenticatedMessage = "登录状态已失效，请重新登录"
)

// Middleware 返回一个 bee.Handler，从请求头 Authorization 里解析 token 并校验登录态。
// 校验通过后把 uid 写入 ctx 的 AccountInfo 并放行；校验失败则写回未登录错误并终止后续处理。
// 只能注册到 bee.HttpServer 上（依赖 Next() 真正串联调用链）。
func Middleware(rdsName string) bee.Handler {
	return func(ctx bee.IContext) {
		token := extractToken(ctx.GetHeader("Authorization"))
		uid, err := Verify(rdsName, token)
		if err != nil {
			// ResponseError 内部已经 Abort，HTTP 状态码仍是 200，错误码走 Code 响应头。
			ctx.ResponseError(UnauthenticatedCode, UnauthenticatedMessage)
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
