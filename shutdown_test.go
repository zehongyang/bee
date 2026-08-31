package bee

import (
	"context"
	"net"
	"testing"
	"time"
)

// newIdleSession 造一个不带真实连接的会话，用来单独驱动 closeIdle。
// handler 和 sm 必须给：Session.Close 会遍历 local handler、按 uid 摘会话。
func newIdleSession(handler *socketHandler, sm *SessionManager) *Session {
	ses := &Session{handler: handler, sm: sm}
	ses.setState(connStateIdle)
	return ses
}

func TestTcpServerShutdownStopsListening(t *testing.T) {
	addr := freeAddr(t)
	server := NewTcpServer()
	runErr := make(chan error, 1)
	go func() { runErr <- server.Run(addr) }()
	waitListening(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() = %v, 期望 nil", err)
	}

	select {
	case err := <-runErr:
		// listener 被 Shutdown 关掉之后 Accept 必然报错，那是正常退出。
		// 这里同时也在防回归：原来的 Accept 循环出错不 continue，会拿 nil conn 继续跑。
		if err != nil {
			t.Fatalf("Run() = %v, 期望 nil（Shutdown 关闭监听属于正常退出）", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown 之后 Run 没有返回")
	}

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("Shutdown 之后端口仍然可以连上")
	}
}

func TestTcpServerCloseIdleReturnsWhenSessionGoesIdle(t *testing.T) {
	server := NewTcpServer()
	ses := newIdleSession(server.handler, server.sm)
	ses.setState(connStateActive)
	server.conns[ses] = struct{}{}

	go func() {
		time.Sleep(100 * time.Millisecond)
		ses.setState(connStateIdle)
	}()

	// 预算给足 5 秒。回归点：原来 closeIdle 只 select ctx.Done()，
	// 只要有一个活跃连接就会一直睡到超时，等于每次关闭都必然等满整个预算。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := server.closeIdle(ctx); err != nil {
		t.Fatalf("closeIdle() = %v, 期望 nil", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("closeIdle 耗时 %v，说明没有轮询而是等满了预算", elapsed)
	}
	if len(server.conns) != 0 {
		t.Fatalf("剩余连接数 = %d, 期望 0", len(server.conns))
	}
}

func TestCloseIdleGivesUpWhenBudgetRunsOut(t *testing.T) {
	server := NewTcpServer()
	ses := newIdleSession(server.handler, server.sm)
	ses.setState(connStateActive) // 一直不空闲，模拟迟迟不结束的请求
	server.conns[ses] = struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := server.closeIdle(ctx); err == nil {
		t.Fatal("closeIdle() = nil, 期望返回超时错误：预算用完必须放弃等待，不能挂住进程")
	}
}

func TestWebSocketServerShutdownStopsListening(t *testing.T) {
	addr := freeAddr(t)
	server := NewWebSocketServer(WithWsPath("/ws"))
	runErr := make(chan error, 1)
	go func() { runErr <- server.Run(addr) }()
	waitListening(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() = %v, 期望 nil", err)
	}
	if !server.shutDown.Load() {
		t.Fatal("Shutdown 之后标志位没有置上，新的握手请求不会被拒")
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run() = %v, 期望 nil（ErrServerClosed 属于正常退出）", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown 之后 Run 没有返回")
	}
}

// TestWebSocketServersUseOwnMux 防的是回退到 http.DefaultServeMux：
// 那样同进程里起第二个 WebSocket server 会因为路径重复注册直接 panic。
func TestWebSocketServersUseOwnMux(t *testing.T) {
	NewWebSocketServer(WithWsPath("/ws"))
	NewWebSocketServer(WithWsPath("/ws"))
}
