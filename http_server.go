package bee

import (
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/golang/protobuf/proto"
	"github.com/zehongyang/bee/logger"
)

var _ IContext = (*HttpContext)(nil)

type HttpContext struct {
	ctx *gin.Context
}

type RouterGroup struct {
	*gin.RouterGroup
}

func (c *HttpContext) Bind(obj any) error {
	return c.ctx.Bind(obj)
}

func (c *HttpContext) GetAccount() AccountInfo {
	value, exists := c.ctx.Get(AccountInfoKey)
	if exists {
		return *(value.(*AccountInfo))
	}
	return AccountInfo{}
}

func (c *HttpContext) ResponseOk(obj any) {
	var data []byte
	var err error
	var contentType = binding.MIMEJSON
	if obj != nil {
		switch c.ctx.ContentType() {
		default:
			data, err = json.Marshal(obj)
		case binding.MIMEPROTOBUF:
			contentType = binding.MIMEPROTOBUF
			message, ok := obj.(proto.Message)
			if !ok {
				logger.Error().Any("obj", obj).Msg("not proto message")
			} else {
				data, err = proto.Marshal(message)
			}
		}
	}
	if err != nil {
		logger.Error().Err(err).Msg("response error")
	}
	c.ctx.Header(HeaderCode, strconv.Itoa(http.StatusOK))
	c.ctx.Data(http.StatusOK, contentType, data)
}

// ResponseBytes 把二进制内容写回客户端，Code 头与 ResponseOk 保持一致（200），
// 让客户端可以用同一套"先看 Code 头再决定怎么读 body"的逻辑处理下载接口。
func (c *HttpContext) ResponseBytes(contentType string, filename string, data []byte) {
	if contentType == "" {
		contentType = MIMEOctetStream
	}
	c.ctx.Header(HeaderCode, strconv.Itoa(http.StatusOK))
	if filename != "" {
		c.ctx.Header(HeaderContentDisposition, contentDisposition(filename))
	}
	c.ctx.Data(http.StatusOK, contentType, data)
}

// contentDisposition 按 RFC 6266 / RFC 5987 组装下载头。
//
// 同时给出 ASCII 回退名和 UTF-8 编码名：只写 filename= 的话，中文名在部分客户端会乱码
// 或被整个丢弃；只写 filename*= 的话，个别老客户端又认不出来。两个都写是通行做法。
func contentDisposition(filename string) string {
	var ascii strings.Builder
	for _, r := range filename {
		// 非 ASCII、控制字符和会破坏引号包裹的字符统一换成下划线。
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			ascii.WriteByte('_')
			continue
		}
		ascii.WriteRune(r)
	}
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`,
		ascii.String(), url.PathEscape(filename))
}

func (c *HttpContext) ResponseError(code int, msg ...string) {
	c.ctx.Abort()
	c.ctx.Header(HeaderCode, strconv.Itoa(code))
	if len(msg) > 0 {
		c.ctx.Header(HeaderError, url.QueryEscape(msg[0]))
	}
	var contentType = binding.MIMEPROTOBUF
	if c.ctx.ContentType() != binding.MIMEPROTOBUF {
		contentType = binding.MIMEJSON
	}
	c.ctx.Data(http.StatusOK, contentType, nil)
}

func (c *HttpContext) Next() {
	c.ctx.Next()
}

func (c *HttpContext) AbortWithStatus(code int) {
	c.ctx.AbortWithStatus(code)
}

func (c *HttpContext) SetAccount(account AccountInfo) {
	c.ctx.Set(AccountInfoKey, &account)
}

func (c *HttpContext) SetHeader(key, value string) {
	c.ctx.Header(key, value)
}

func (c *HttpContext) GetHeader(key string) string {
	return c.ctx.GetHeader(key)
}

func (c *HttpContext) BindHeader(obj any) error {
	return c.ctx.BindHeader(obj)
}

func (c *HttpContext) BindUri(obj any) error {
	return c.ctx.BindUri(obj)
}

func (c *HttpContext) GetMethod() string {
	return c.ctx.Request.Method
}

// Context 返回底层 HTTP 请求的 context。客户端断开连接时它会被取消，
// 业务侧把它一路传给数据库和第三方调用，就不会在客户端已经走掉之后还继续消耗资源。
func (c *HttpContext) Context() context.Context {
	return c.ctx.Request.Context()
}

// Query 返回 URL 查询参数的值，参数不存在时返回空字符串。
// 刻意不复用 gin 的 Bind 来读查询参数：Bind 在解析失败时会直接写出 400 并中断请求，
// 而本框架约定业务错误一律走 HTTP 200 + 响应体里的 error 字段（见 envelope.go）。
// handler 自己按字符串解析，才能把格式错误也翻译成统一的业务错误码。
func (c *HttpContext) Query(key string) string {
	return c.ctx.Query(key)
}

func (c *HttpContext) FormFile(name string) (*multipart.FileHeader, error) {
	return c.ctx.FormFile(name)
}

func (c *HttpContext) GetIp() string {
	return c.ctx.ClientIP()
}

// GetPath 返回当前请求命中的路由模板路径，例如 "/api/v1/meetings/:id"。
func (c *HttpContext) GetPath() string {
	return c.ctx.FullPath()
}

// GetStatus 返回底层 gin ResponseWriter 已经写出的 HTTP 状态码。
func (c *HttpContext) GetStatus() int {
	return c.ctx.Writer.Status()
}

// Set 把键值对存入 gin.Context 自带的请求级存储，供同一次请求内的中间件和 handler 共享。
func (c *HttpContext) Set(key string, value any) {
	c.ctx.Set(key, value)
}

// Get 从 gin.Context 自带的请求级存储中读取 Set 存入的值。
func (c *HttpContext) Get(key string) (any, bool) {
	return c.ctx.Get(key)
}

type HttpServer struct {
	engine *gin.Engine
}

func NewHttpServer() *HttpServer {
	return &HttpServer{
		engine: gin.Default(),
	}
}

// ServeHTTP 让 HttpServer 满足标准库的 http.Handler，可以直接交给 httptest 驱动，
// 也方便把它挂到外层的 http.Server 上做优雅关闭。
func (s *HttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.engine.ServeHTTP(w, r)
}

func (s *HttpServer) Run(addr string) error {
	logger.Info().Any("addr", addr).Msg("http server running")
	return s.engine.Run(addr)
}

func (s *HttpServer) Register(httpMethod, relativePath string, handler Handler) {
	s.engine.Handle(httpMethod, relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

func (s *HttpServer) Post(relativePath string, handler Handler) {
	s.engine.POST(relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

func (s *HttpServer) Get(relativePath string, handler Handler) {
	s.engine.GET(relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

func (s *HttpServer) Use(handler Handler) {
	s.engine.Use(func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

func (s *HttpServer) Group(relativePath string) *RouterGroup {
	return &RouterGroup{s.engine.Group(relativePath)}
}

func (s *RouterGroup) Post(relativePath string, handler Handler) {
	s.RouterGroup.POST(relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

// Get 在路由分组下注册一个 GET 路由，与 RouterGroup.Post 对称。
func (s *RouterGroup) Get(relativePath string, handler Handler) {
	s.RouterGroup.GET(relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

// Register 在路由分组下注册任意 HTTP 方法的路由，与 HttpServer.Register 对称。
func (s *RouterGroup) Register(httpMethod, relativePath string, handler Handler) {
	s.RouterGroup.Handle(httpMethod, relativePath, func(c *gin.Context) {
		handler(&HttpContext{
			ctx: c,
		})
	})
}

func (s *RouterGroup) Use(handlers ...Handler) {
	for _, handler := range handlers {
		s.RouterGroup.Use(func(c *gin.Context) {
			handler(&HttpContext{ctx: c})
		})
	}
}
