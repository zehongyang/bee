package bee

import (
	"context"
	"mime/multipart"
)

type connState int

const (
	HeaderCode  = "Code"
	HeaderError = "Error"
	// HeaderContentDisposition 用于下载响应，告诉客户端这是附件以及建议的文件名。
	HeaderContentDisposition = "Content-Disposition"
	// MIMEOctetStream 是二进制响应在调用方没指定类型时的兜底 Content-Type。
	MIMEOctetStream           = "application/octet-stream"
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
	// ResponseBytes 直接把二进制内容作为响应体返回，用于下载文件这类不适合走 JSON 的场景
	// （base64 塞进 JSON 会平白多传三分之一）。
	//
	// 与 ResponseOk 一样把 Code 头置为 200，所以客户端的判成败逻辑不用改：先看 Code 头，
	// 是 200 才把响应体当文件读。失败路径仍然走 ResponseError（空体 + Code/Error 头）。
	//
	// filename 非空时会写 Content-Disposition 触发浏览器下载，中文文件名按 RFC 5987 编码。
	// 只有 HTTP 场景有意义，WebSocket/TCP 的实现是空操作。
	ResponseBytes(contentType string, filename string, data []byte)
	// ResponseRaw 按调用方指定的 HTTP 状态码原样写回响应体，不写 Code 头。
	//
	// 这是一个刻意开的口子，只给第三方 Webhook 应答用：支付渠道的回调协议是对方定的，
	// 微信要 JSON 且靠 HTTP 状态码判断成败（非 2xx 才会重推），支付宝要纯文本 success，
	// 都不认本框架"状态码恒 200 + Code 头"的约定。
	//
	// 业务接口一律不要用它——用了客户端就没法按同一套逻辑判成败。
	// 只有 HTTP 场景有意义，WebSocket/TCP 的实现是空操作。
	ResponseRaw(statusCode int, contentType string, data []byte)
	ResponseError(code int, msg ...string)
	Next()
	AbortWithStatus(code int)
	SetAccount(account AccountInfo)
	GetHeader(key string) string
	SetHeader(key, value string)
	// GetRawBody 返回本次请求体的原始字节，且不影响之后再调用 Bind。
	//
	// 存在的理由是第三方 Webhook 验签：签名是对报文原文算出来的，Bind 成结构体再
	// 重新序列化，字段顺序、空格、数字格式都可能变，签名必然对不上。所以验签这类场景
	// 必须拿到一字节不差的原文。
	//
	// 请求没有 body 时返回 nil, nil。
	GetRawBody() ([]byte, error)
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
