package bee

import (
	"context"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ctxValueKey 是存入 context.Context 的自定义 key 类型，避免和其他包的字符串 key 冲突。
type ctxValueKey string

type WebSocketData struct {
	ContentType int    `json:"content_type"`
	Fid         int    `json:"fid"`
	Qid         int    `json:"qid"`
	Code        int    `json:"code"`
	Data        []byte `json:"data"`
}

var _ IContext = (*WebSocketContext)(nil)

type WebSocketContext struct {
	ctx     context.Context
	session *Session
	data    *WebSocketData
}

func (c *WebSocketContext) Bind(obj any) error {
	switch c.data.ContentType {
	default:
		return json.Unmarshal(c.data.Data, obj)
	case int(ContentTypeProtobuf):
		msg, ok := obj.(proto.Message)
		if !ok {
			return ErrProtoObj
		}
		return proto.Unmarshal(c.data.Data, msg)
	}
}

func (c *WebSocketContext) GetAccount() AccountInfo {
	return c.session.account
}

func (c *WebSocketContext) ResponseOk(obj any) {
	var data []byte
	var err error
	var code = http.StatusOK
	if obj != nil {
		switch c.data.ContentType {
		default:
			data, err = json.Marshal(obj)
			if err != nil {
				code = http.StatusInternalServerError
				logger.Error().Err(err).Any("obj", obj).Msg("ResponseOk")
			}
		case int(ContentTypeProtobuf):
			msg, ok := obj.(proto.Message)
			if !ok {
				code = http.StatusInternalServerError
				logger.Error().Any("obj", obj).Msg("ResponseOk")
			} else {
				data, err = proto.Marshal(msg)
				if err != nil {
					code = http.StatusInternalServerError
					logger.Error().Err(err).Any("obj", obj).Msg("ResponseOk")
				}
			}
		}
	}
	c.data.Code = code
	c.data.Data = data
	rd, err := json.Marshal(c.data)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("ResponseOk")
		return
	}
	_, err = c.session.Write(rd)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("ResponseOk")
	}
}

func (c *WebSocketContext) ResponseError(code int, msg ...string) {
	c.data.Code = code
	c.data.Data = nil
	rd, err := json.Marshal(c.data)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("ResponseError")
		return
	}
	_, err = c.session.Write(rd)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("ResponseError")
	}
}

func (c *WebSocketContext) Next() {
	return
}

func (c *WebSocketContext) AbortWithStatus(code int) {
	c.data.Code = code
	c.data.Data = nil
	rd, err := json.Marshal(c.data)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("AbortWithStatus")
		return
	}
	_, err = c.session.Write(rd)
	if err != nil {
		logger.Error().Err(err).Any("uid", c.session.uid).Any("fid", c.data.Fid).Msg("AbortWithStatus")
	}
}

func (c *WebSocketContext) SetAccount(account AccountInfo) {
	c.session.account = account
	c.session.uid = int64(account.Uid)
}

func (c *WebSocketContext) SetHeader(key, value string) {
	return
}

func (c *WebSocketContext) GetHeader(key string) string {
	return ""
}

func (c *WebSocketContext) BindHeader(obj any) error {
	return nil
}

func (c *WebSocketContext) BindUri(obj any) error {
	return nil
}

func (c *WebSocketContext) GetMethod() string {
	return ""
}

func (c *WebSocketContext) FormFile(name string) (*multipart.FileHeader, error) {
	return nil, nil
}

func (c *WebSocketContext) GetIp() string {
	return ""
}

// GetPath 在 WebSocket 场景下没有 URL 路径概念，用 fid 的字符串形式代替，方便日志区分业务功能。
func (c *WebSocketContext) GetPath() string {
	return strconv.Itoa(c.data.Fid)
}

// GetStatus 返回本次响应写回的业务状态码。
func (c *WebSocketContext) GetStatus() int {
	return c.data.Code
}

// Set 把键值对存入本次消息处理的 context.Context 里，供同一次调用链内的中间件和 handler 共享。
func (c *WebSocketContext) Set(key string, value any) {
	c.ctx = context.WithValue(c.ctx, ctxValueKey(key), value)
}

// Get 从 context.Context 中读取 Set 存入的值。
func (c *WebSocketContext) Get(key string) (any, bool) {
	v := c.ctx.Value(ctxValueKey(key))
	return v, v != nil
}

type WebSocketServer struct {
	opts     *SocketOptions
	sm       *SessionManager
	handler  *socketHandler
	upgrader *websocket.Upgrader
	pool     *sync.Pool
	mu       sync.Mutex
	conns    map[*Session]struct{}
	shutDown bool
}

func NewWebSocketServer(options ...OptionFun) *WebSocketServer {
	var opts SocketOptions
	if len(options) > 0 {
		for _, option := range options {
			option(&opts)
		}
	}
	if opts.readTimeout < 1 {
		opts.readTimeout = defaultReadTimeout
	}
	if opts.writeTimeout < 1 {
		opts.writeTimeout = defaultWriteTimeout
	}
	hd := &socketHandler{
		handlers: make(map[int64]Handler),
		local:    make(map[int64]Handler),
	}
	return &WebSocketServer{opts: &opts, sm: NewSessionManager(), conns: map[*Session]struct{}{}, handler: hd,
		upgrader: &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}, pool: &sync.Pool{New: func() interface{} {
			return &WebSocketContext{}
		}}}
}

func (s *WebSocketServer) Run(addr, wsPath string) error {
	http.HandleFunc(wsPath, s.serveWs)
	log.Println("websocket running on addr", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *WebSocketServer) serveWs(w http.ResponseWriter, r *http.Request) {
	if s.shutDown {
		logger.Info().Msg("websocket server is shutting down")
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error().Err(err).Msg("serveWs")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	go s.handle(conn)
}

func (s *WebSocketServer) handle(conn *websocket.Conn) {
	var ses = &Session{
		mu:           sync.Mutex{},
		readTimeout:  s.opts.readTimeout,
		writeTimeout: s.opts.writeTimeout,
		sm:           s.sm,
		handler:      s.handler,
		wsConn:       conn,
	}
	defer func() {
		ses.Close(true)
		if err := recover(); err != nil {
			stack := utils.Stack(2)
			logger.Error().Str("stack", string(stack)).Msg("WebSocketServer serve")
		}
	}()
	s.mu.Lock()
	s.conns[ses] = struct{}{}
	s.mu.Unlock()
	ses.setState(connStateNew)
	var err error
	for {
		err = ses.wsConn.SetReadDeadline(time.Now().Add(s.opts.readTimeout))
		if err != nil {
			logger.Error().Err(err).Any("uid", ses.uid).Msg("handleWs")
			return
		}
		wd, err := ses.readFromWebSocket()
		if err != nil {
			logger.Error().Err(err).Any("uid", ses.uid).Msg("handleWs")
			return
		}
		if wd != nil && !s.shutDown {
			hd, ok := s.handler.handlers[int64(wd.Fid)]
			if ok {
				wc := s.pool.Get()
				webCtx := wc.(*WebSocketContext)
				webCtx.ctx = context.Background()
				webCtx.session = ses
				webCtx.data = wd
				ses.setState(connStateActive)
				hd(webCtx)
				ses.setState(connStateIdle)
				s.pool.Put(webCtx)
			} else {
				logger.Error().Err(err).Any("uid", ses.uid).Msg("not found handler")
			}
		}
	}
}

func (s *WebSocketServer) Register(fid int64, h Handler) {
	s.handler.handlers[fid] = h
}

func (s *WebSocketServer) RegisterLocal(fid int64, h Handler) {
	s.handler.local[fid] = h
}

func (s *WebSocketServer) Shutdown() {
	s.shutDown = true
	ctx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(time.Second*5))
	defer cancelFunc()
	err := s.closeIdle(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("tcp server shutdown")
	}
}

func (s *WebSocketServer) closeIdle(ctx context.Context) error {
	for {
		var finished = true
		s.mu.Lock()
		for ses, _ := range s.conns {
			state, _ := ses.getState()
			if state == connStateActive {
				finished = false
				continue
			}
			ses.Close(true)
			delete(s.conns, ses)
		}
		s.mu.Unlock()
		if finished {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
