package bee

import (
	"context"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/zehongyang/bee/logger"
	"net/http"
	"sync"
	"time"
)

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

type WebSocketServer struct {
	opts     *SocketOptions
	sm       *SessionManager
	handler  *socketHandler
	upgrader *websocket.Upgrader
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
	return &WebSocketServer{opts: &opts, sm: NewSessionManager(), handler: hd, upgrader: &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}}
}

func (s *WebSocketServer) Run(addr, wsPath string) error {
	http.HandleFunc(wsPath, s.serveWs)
	return http.ListenAndServe(addr, nil)
}

func (s *WebSocketServer) serveWs(w http.ResponseWriter, r *http.Request) {
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
	defer ses.Close()
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
		if wd != nil {
			hd, ok := s.handler.handlers[int64(wd.Fid)]
			if ok {
				go func() {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					hd(&WebSocketContext{
						ctx:     ctx,
						session: ses,
						data:    wd,
					})
				}()
			} else {
				logger.Error().Err(err).Any("uid", ses.uid).Msg("not found handler")
			}
		}
	}
}
