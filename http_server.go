package bee

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/golang/protobuf/proto"
	"github.com/zehongyang/bee/logger"
	"net/http"
	"net/url"
	"strconv"
)

var _ IContext = (*HttpContext)(nil)

type HttpContext struct {
	ctx *gin.Context
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

func (c *HttpContext) ResponseError(code int, msg ...string) {
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

type HttpServer struct {
	engine *gin.Engine
}

func NewHttpServer() *HttpServer {
	return &HttpServer{
		engine: gin.Default(),
	}
}

func (s *HttpServer) Run(addr string) error {
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
