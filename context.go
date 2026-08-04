package bee

import (
	"context"
	"mime/multipart"
)

type connState int

const (
	HeaderCode                = "Code"
	HeaderError               = "Error"
	AccountInfoKey            = "Account"
	connStateNew    connState = 1
	connStateActive connState = 2
	connStateIdle   connState = 3
)

type AccountInfo struct {
	Uid int64
}

func (a AccountInfo) GetUid() int64 {
	return a.Uid
}

type Handler func(ctx IContext)

type IContext interface {
	Bind(obj any) error
	GetAccount() AccountInfo
	ResponseOk(obj any)
	ResponseError(code int, msg ...string)
	Next()
	AbortWithStatus(code int)
	SetAccount(account AccountInfo)
	GetHeader(key string) string
	SetHeader(key, value string)
	BindHeader(obj any) error
	BindUri(obj any) error
	GetMethod() string
	// Query 返回 URL 查询参数的值，参数不存在时返回空字符串。
	// 只有 HTTP 场景有查询参数，WebSocket/TCP 的实现固定返回空字符串。
	Query(key string) string
	// Context 返回本次请求的 context，客户端断开时会被取消，用于向下游传递超时和取消信号。
	// WebSocket/TCP 的实现返回 context.Background()。
	Context() context.Context
	FormFile(name string) (*multipart.FileHeader, error)
	GetIp() string
	// GetPath 返回当前请求命中的路由路径，WebSocket/TCP 场景下返回对应的 Fid 字符串。
	GetPath() string
	// GetStatus 返回当前请求最终响应的业务状态码（对应 HeaderCode 或协议自身的 Code 字段）。
	GetStatus() int
	// Set 把一个键值对挂在当前请求的上下文里，供同一次请求内的中间件和 handler 之间传值，例如 request_id。
	Set(key string, value any)
	// Get 读取 Set 存入的值，第二个返回值表示对应的 key 是否存在。
	Get(key string) (any, bool)
}
