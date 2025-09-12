package bee

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type Platform int
type ClientOs int

type ContentType int

type OptionFun func(o *SocketOptions)

const (
	ContentTypeJson     ContentType = 0
	ContentTypeProtobuf ContentType = 1
	Version                         = 1
	PlatformMobile      Platform    = 0
	PlatformDesktop     Platform    = 1
	ClientAndroid       ClientOs    = 1
	ClientIos           ClientOs    = 2
	ClientWindows       ClientOs    = 3
	ClientMac           ClientOs    = 4
	defaultReadTimeout              = time.Second * 60
	defaultWriteTimeout             = time.Second * 10
)

type Package struct {
	Version     int8
	ContentType int8
	Fid         int32
	Qid         int32
	Code        int32
	Length      int32
	Data        []byte
}

func (p *Package) Read(rd io.Reader) error {
	var data = make([]byte, 1)
	_, err := io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.Version = int8(data[0])
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	if p.Version != Version {
		return ErrUnSupportVersion
	}
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.ContentType = int8(data[0])
	if p.ContentType != int8(ContentTypeJson) && p.ContentType != int8(ContentTypeProtobuf) {
		return ErrContentType
	}
	data = make([]byte, 4)
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.Fid = int32(binary.BigEndian.Uint32(data))
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.Qid = int32(binary.BigEndian.Uint32(data))
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.Code = int32(binary.BigEndian.Uint32(data))
	_, err = io.ReadFull(rd, data)
	if err != nil {
		return err
	}
	p.Length = int32(binary.BigEndian.Uint32(data))
	p.Data = make([]byte, p.Length)
	_, err = io.ReadFull(rd, p.Data)
	return err
}

func (p *Package) Marshal(fid int32, code int32, data []byte) []byte {
	if fid < 1 {
		fid = p.Fid
	}
	var buf = make([]byte, len(data)+14)
	buf[0] = byte(p.Version)
	buf[1] = byte(p.ContentType)
	binary.BigEndian.PutUint32(buf[2:6], uint32(fid))
	binary.BigEndian.PutUint32(buf[6:10], uint32(code))
	binary.BigEndian.PutUint32(buf[10:14], uint32(len(data)))
	copy(buf[14:], data)
	return buf
}

type Session struct {
	conn         net.Conn
	mu           sync.Mutex
	os           ClientOs
	uid          int64
	account      AccountInfo
	readTimeout  time.Duration
	writeTimeout time.Duration
	sm           *SessionManager
	handler      *socketHandler
	wsConn       *websocket.Conn
}

func (s *Session) readFromTcp() (*Package, error) {
	var pkg Package
	err := pkg.Read(s.conn)
	if err != nil {
		return nil, err
	}
	return &pkg, err
}

func (s *Session) readFromWebSocket() (*WebSocketData, error) {
	var wd WebSocketData
	err := s.wsConn.ReadJSON(&wd)
	return &wd, err
}

func (s *Session) Close() {
	if s.uid > 0 {
		s.sm.Remove(s.uid, getPlatform(s.os))
	}
	for _, handler := range s.handler.local {
		var ctx TcpContext
		handler(&ctx)
	}
}

func (s *Session) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wsConn != nil {
		err := s.wsConn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		if err != nil {
			return 0, err
		}
		err = s.wsConn.WriteMessage(websocket.BinaryMessage, data)
		return len(data), err
	}
	err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	if err != nil {
		return 0, err
	}
	return s.conn.Write(data)
}

func (s *Session) WriteEvent(fid int32, contentType ContentType, data []byte) (int, error) {
	var pkg = Package{
		Version:     Version,
		ContentType: int8(contentType),
	}
	wd := pkg.Marshal(fid, pkg.Code, data)
	return s.Write(wd)
}

var _ IContext = (*TcpContext)(nil)

type TcpContext struct {
	ctx     context.Context
	session *Session
	pkg     *Package
}

func (t *TcpContext) Bind(obj any) error {
	switch t.pkg.ContentType {
	default:
		return json.Unmarshal(t.pkg.Data, obj)
	case int8(ContentTypeProtobuf):
		msg, ok := obj.(proto.Message)
		if !ok {
			return ErrProtoObj
		}
		return proto.Unmarshal(t.pkg.Data, msg)
	}
}

func (t *TcpContext) GetAccount() AccountInfo {
	return t.session.account
}

func (t *TcpContext) ResponseOk(obj any) {
	var data []byte
	var err error
	var code = http.StatusOK
	if obj != nil {
		switch t.pkg.ContentType {
		default:
			data, err = json.Marshal(obj)
			if err != nil {
				logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseOk")
				code = http.StatusInternalServerError
			}
		case int8(ContentTypeProtobuf):
			msg, ok := obj.(proto.Message)
			if ok {
				data, err = proto.Marshal(msg)
				if err != nil {
					logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseOk")
					code = http.StatusInternalServerError
				}
			} else {
				logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseOk")
				code = http.StatusInternalServerError
			}
		}
	}
	t.pkg.Code = int32(code)
	wd := t.pkg.Marshal(t.pkg.Fid, int32(code), data)
	_, err = t.session.Write(wd)
	if err != nil {
		logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseOk")
	}
}

func (t *TcpContext) ResponseError(code int, msg ...string) {
	t.pkg.Code = int32(code)
	wd := t.pkg.Marshal(t.pkg.Fid, int32(code), nil)
	_, err := t.session.Write(wd)
	if err != nil {
		logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseError")
	}
}

func (t *TcpContext) Next() {
	return
}

func (t *TcpContext) AbortWithStatus(code int) {
	t.pkg.Code = int32(code)
	wd := t.pkg.Marshal(t.pkg.Fid, int32(code), nil)
	_, err := t.session.Write(wd)
	if err != nil {
		logger.Error().Err(err).Any("uid", t.session.uid).Any("fid", t.pkg.Fid).Msg("ResponseError")
	}
}

func (t *TcpContext) SetAccount(account AccountInfo) {
	t.session.account = account
	t.session.uid = int64(account.Uid)
}

func (t *TcpContext) SetHeader(key, value string) {
	return
}

func (t *TcpContext) GetHeader(key string) string {
	return ""
}

func (t *TcpContext) BindHeader(obj any) error {
	return nil
}

func (t *TcpContext) BindUri(obj any) error {
	return nil
}

type SessionManager struct {
	buckets []*SessionBucket
}

var NewSessionManager = utils.Single(func() *SessionManager {
	var size = 128
	var buckets = make([]*SessionBucket, size)
	for i := 0; i < size; i++ {
		buckets[i] = &SessionBucket{mp: make(map[int64][2]*Session)}
	}
	return &SessionManager{buckets: buckets}
})

func (m *SessionManager) Insert(ses *Session) *Session {
	idx := ses.uid % int64(len(m.buckets))
	platform := getPlatform(ses.os)
	bucket := m.buckets[idx]
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	old := bucket.mp[ses.uid][platform]
	arr := bucket.mp[ses.uid]
	arr[platform] = ses
	return old
}

func (m *SessionManager) RemoveAll(uid int64) []*Session {
	idx := uid % int64(len(m.buckets))
	bucket := m.buckets[idx]
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	ses := bucket.mp[uid]
	bucket.mp[uid] = [2]*Session{}
	return ses[:]
}

func (m *SessionManager) Remove(uid int64, platform Platform) *Session {
	idx := uid % int64(len(m.buckets))
	bucket := m.buckets[idx]
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	arr := bucket.mp[uid]
	ses := arr[platform]
	arr[platform] = nil
	return ses
}

func (m *SessionManager) Get(uid int64, os ClientOs) *Session {
	idx := uid % int64(len(m.buckets))
	platform := getPlatform(os)
	bucket := m.buckets[idx]
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	return bucket.mp[uid][platform]
}

func (m *SessionManager) GetAll(uid int64) []*Session {
	idx := uid % int64(len(m.buckets))
	bucket := m.buckets[idx]
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	ses := bucket.mp[uid]
	return ses[:]
}

func getPlatform(os ClientOs) Platform {
	switch os {
	default:
		return PlatformMobile
	case ClientAndroid, ClientIos:
		return PlatformMobile
	case ClientWindows, ClientMac:
		return PlatformDesktop
	}
}

type SessionBucket struct {
	mu sync.RWMutex
	mp map[int64][2]*Session
}

type TcpServer struct {
	listener net.Listener
	options  *SocketOptions
	sm       *SessionManager
	handler  *socketHandler
	pool     *sync.Pool
}

type socketHandler struct {
	handlers map[int64]Handler
	local    map[int64]Handler
}

type SocketOptions struct {
	readTimeout  time.Duration
	writeTimeout time.Duration
	cert         *tls.Certificate
	certFile     string
	keyFile      string
}

func (t *SocketOptions) init() error {
	if t.readTimeout == 0 {
		t.readTimeout = defaultReadTimeout
	}
	if t.writeTimeout == 0 {
		t.writeTimeout = defaultWriteTimeout
	}
	if len(t.certFile) > 0 && len(t.keyFile) > 0 {
		cert, err := tls.LoadX509KeyPair(t.certFile, t.keyFile)
		if err != nil {
			return err
		}
		t.cert = &cert
	}
	return nil
}

func WithReadTimeout(readTimeout time.Duration) OptionFun {
	return func(o *SocketOptions) {
		o.readTimeout = readTimeout
	}
}

func WithWriteTimeout(writeTimeout time.Duration) OptionFun {
	return func(o *SocketOptions) {
		o.writeTimeout = writeTimeout
	}
}

func WithCert(certFile string, keyFile string) OptionFun {
	return func(o *SocketOptions) {
		o.certFile = certFile
		o.keyFile = keyFile
	}
}

func NewTcpServer(bucketSize int, options ...OptionFun) *TcpServer {
	var op SocketOptions
	if len(options) > 0 {
		for _, opFun := range options {
			opFun(&op)
		}
	}
	var handler socketHandler
	handler.handlers = make(map[int64]Handler)
	handler.local = make(map[int64]Handler)
	return &TcpServer{options: &op, sm: NewSessionManager(), handler: &handler, pool: &sync.Pool{New: func() interface{} {
		return &TcpContext{}
	}}}
}

func (s *TcpServer) Run(addr string) error {
	var err error
	if s.options.cert == nil {
		s.listener, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
	} else {
		s.listener, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{*s.options.cert}})
		if err != nil {
			return err
		}
	}
	log.Println("tcp server listening on", addr)
	defer s.listener.Close()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			logger.Error().Err(err).Any("addr", s.listener.Addr()).Msg("tcp server accept")
		}
		go s.serve(conn)
	}
}

func (s *TcpServer) serve(conn net.Conn) {
	var ses = Session{
		conn:         conn,
		readTimeout:  s.options.readTimeout,
		writeTimeout: s.options.writeTimeout,
		handler:      s.handler,
		sm:           s.sm,
	}
	defer ses.Close()
	for {
		err := ses.conn.SetReadDeadline(time.Now().Add(s.options.readTimeout))
		if err != nil {
			logger.Debug().Err(err).Msg("set read deadline")
			return
		}
		pkg, err := ses.readFromTcp()
		if err != nil {
			logger.Debug().Err(err).Msg("read data")
			return
		}
		if pkg != nil {
			handler, ok := ses.handler.handlers[int64(pkg.Fid)]
			if !ok {
				logger.Error().Any("fid", pkg.Fid).Msg("not found handler")
			} else {
				go func() {
					tc := s.pool.Get()
					tcpContext := tc.(*TcpContext)
					ctx, cancel := context.WithCancel(context.Background())
					defer func() {
						cancel()
						s.pool.Put(tcpContext)
					}()
					tcpContext.ctx = ctx
					tcpContext.session = &ses
					tcpContext.pkg = pkg
					handler(tcpContext)
				}()
			}
		}
	}
}

func (s *TcpServer) Register(fid int64, h Handler) {
	s.handler.handlers[fid] = h
}

func (s *TcpServer) RegisterLocal(fid int64, h Handler) {
	s.handler.local[fid] = h
}
