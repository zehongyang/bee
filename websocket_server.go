package bee

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
	"mime/multipart"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// defaultWsPath 是没有用 WithWsPath 指定时的 WebSocket 握手路径。
const defaultWsPath = "/ws"

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

// ResponseBytes 在 WebSocket 场景下是空操作：下载文件是 HTTP 独有的语义，
// 这里静默忽略而不是报错，与 Query、FormFile 的处理方式保持一致。
func (c *WebSocketContext) ResponseBytes(contentType string, filename string, data []byte) {
}

// ResponseRaw 在 WebSocket 场景下没有 HTTP 状态码的概念，是空操作。
func (c *WebSocketContext) ResponseRaw(statusCode int, contentType string, data []byte) {
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

// GetRawBody 返回本次消息的原始载荷。理由同 TcpContext：Bind 只是对 data.Data 做反序列化，
// 不消耗流，取过之后 Bind 照常可用。
func (c *WebSocketContext) GetRawBody() ([]byte, error) {
	return c.data.Data, nil
}

func (c *WebSocketContext) BindUri(obj any) error {
	return nil
}

func (c *WebSocketContext) GetMethod() string {
	return ""
}

// Query 在 WebSocket 场景下没有对应概念，固定返回空字符串。
func (c *WebSocketContext) Query(key string) string {
	return ""
}

// Context 在 WebSocket 场景下没有对应的请求生命周期，返回 context.Background()。
func (c *WebSocketContext) Context() context.Context {
	return context.Background()
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
	srv      *http.Server
	// shutDown 用原子量：写在 Shutdown 所在的 goroutine，读在每个连接的读循环里。
	shutDown atomic.Bool
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
	if len(opts.wsPath) < 1 {
		opts.wsPath = defaultWsPath
	}
	hd := &socketHandler{
		handlers: make(map[int64]Handler),
		local:    make(map[int64]Handler),
	}
	// 自带 mux 和 http.Server，不再用 http.DefaultServeMux + http.ListenAndServe：
	// 全局 mux 会让同进程里起两个 WebSocket server 直接 panic（重复注册路径），
	// 而 ListenAndServe 不交出 server 句柄，也就没法优雅关闭。
	mux := http.NewServeMux()
	s := &WebSocketServer{opts: &opts, sm: NewSessionManager(), conns: map[*Session]struct{}{}, handler: hd,
		upgrader: &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}, srv: &http.Server{Handler: mux}, pool: &sync.Pool{New: func() interface{} {
			return &WebSocketContext{}
		}}}
	mux.HandleFunc(opts.wsPath, s.serveWs)
	return s
}

// Run 阻塞式启动 WebSocket 监听，直到监听出错或者 Shutdown 被调用。
// 握手路径由 WithWsPath 指定，这样签名和其他 server 一致，可以交给 bee.Run 托管。
func (s *WebSocketServer) Run(addr string) error {
	s.srv.Addr = addr
	logger.Info().Any("addr", addr).Any("path", s.opts.wsPath).Msg("websocket server running")
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// ErrServerClosed 是 Shutdown 触发的正常退出，不是故障。
	return nil
}

func (s *WebSocketServer) serveWs(w http.ResponseWriter, r *http.Request) {
	if s.shutDown.Load() {
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
		if wd != nil && !s.shutDown.Load() {
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

// Shutdown 先拒掉新的握手，再等在途请求处理完才断开已有连接。
// 关闭预算由 ctx 决定（bee.Run 按 shutdown.timeoutSeconds 给）。
func (s *WebSocketServer) Shutdown(ctx context.Context) error {
	// 先置标志：srv.Shutdown 只管 HTTP 层，已经升级成 WebSocket 的连接是被 Hijack 走的，
	// 它不认识、也不会等；正在握手的那些则要靠这个标志当场拒掉。
	s.shutDown.Store(true)
	err := s.srv.Shutdown(ctx)
	if cErr := s.closeIdle(ctx); cErr != nil && err == nil {
		err = cErr
	}
	return err
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
		case <-time.After(closeIdlePollInterval):
			// 还有连接在处理请求，等一会儿再看一轮。理由同 TcpServer.closeIdle。
		}
	}
}
