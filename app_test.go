package bee

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeServer 模拟一个真实 server 的关闭行为：Run 一直阻塞，直到 Shutdown 放它走。
type fakeServer struct {
	mu            sync.Mutex
	events        []string
	runErr        error
	shutdownErr   error
	shutdownDelay time.Duration
	// ignoreCtx 为 true 时 Shutdown 不理会 ctx 取消，用来触发强制退出这条路径。
	ignoreCtx bool
	stopped   chan struct{}
	once      sync.Once
}

func newFakeServer() *fakeServer {
	return &fakeServer{stopped: make(chan struct{})}
}

func (f *fakeServer) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *fakeServer) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeServer) Run(addr string) error {
	f.record("run")
	if f.runErr != nil {
		return f.runErr
	}
	<-f.stopped
	return nil
}

func (f *fakeServer) Shutdown(ctx context.Context) error {
	f.record("shutdown")
	defer f.once.Do(func() { close(f.stopped) })
	if f.shutdownDelay > 0 {
		if f.ignoreCtx {
			time.Sleep(f.shutdownDelay)
		} else {
			select {
			case <-time.After(f.shutdownDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return f.shutdownErr
}

// runInBackground 起一个 goroutine 跑 run，返回取消函数和拿返回值的 channel。
func runInBackground(server Server, timeout time.Duration) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, func() {}, server, "127.0.0.1:0", timeout)
	}()
	return cancel, errCh
}

func TestRunShutsDownServerThenHooks(t *testing.T) {
	server := newFakeServer()
	var order []string
	var mu sync.Mutex
	OnShutdown("hook", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "hook")
		return nil
	})

	cancel, errCh := runInBackground(server, time.Second)
	cancel() // 相当于收到 SIGINT/SIGTERM

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() = %v, 期望 nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run 收到退出信号后没有返回")
	}

	if got := server.recorded(); len(got) != 2 || got[1] != "shutdown" {
		t.Fatalf("server 事件 = %v, 期望关闭时调用了 Shutdown", got)
	}
	mu.Lock()
	defer mu.Unlock()
	// 钩子必须在 server 停下来之后才跑：连接池要等在途请求用完才能关。
	if len(order) != 1 {
		t.Fatalf("清理钩子执行次数 = %d, 期望 1", len(order))
	}
}

func TestRunRunsHooksWhenServerExitsEarly(t *testing.T) {
	cases := []struct {
		name    string
		runErr  error
		wantErr bool
	}{
		{name: "监听失败", runErr: errors.New("address already in use"), wantErr: true},
		{name: "服务自己退出", runErr: nil, wantErr: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := newFakeServer()
			server.runErr = c.runErr
			if c.runErr == nil {
				// runErr 为 nil 时 Run 会阻塞，这里放它直接返回，模拟服务自行退出。
				close(server.stopped)
			}
			var hookRan bool
			OnShutdown("hook", func(ctx context.Context) error {
				hookRan = true
				return nil
			})

			cancel, errCh := runInBackground(server, time.Second)
			defer cancel()

			select {
			case err := <-errCh:
				if c.wantErr && !errors.Is(err, c.runErr) {
					t.Fatalf("run() = %v, 期望包住 %v", err, c.runErr)
				}
				if !c.wantErr && err != nil {
					t.Fatalf("run() = %v, 期望 nil", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server 已经退出，run 却没有返回")
			}

			// 端口被占那种情况下，handler 工厂可能已经把数据库和 Redis 连上了，
			// 直接返回就等于把连接留给进程退出去硬切。
			if !hookRan {
				t.Fatal("server 提前退出时没有执行清理钩子")
			}
		})
	}
}

func TestRunForceExitsWhenShutdownHangs(t *testing.T) {
	server := newFakeServer()
	server.ignoreCtx = true
	server.shutdownDelay = 5 * time.Second

	start := time.Now()
	cancel, errCh := runInBackground(server, 10*time.Millisecond)
	defer cancel()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("run() = %v, 期望 ErrShutdownTimeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("关闭卡住时 run 没有强制退出")
	}
	// 不能等 Shutdown 自己回来：挂着不退只会让编排系统在宽限期结束后 SIGKILL。
	if elapsed := time.Since(start); elapsed >= server.shutdownDelay {
		t.Fatalf("强制退出耗时 %v, 说明还是等到了 Shutdown 返回", elapsed)
	}
}

// TestRunGivesHooksFreshBudget 防的是"钩子跟在途请求抢预算"：
// 一次外部调用就能把总预算耗光（后端的大模型调用配了 90 秒，关闭预算只有 15 秒），
// 那时钩子如果拿到的是同一个已经过期的 ctx，该释放的锁、该关的连接就全都跑不掉。
func TestRunGivesHooksFreshBudget(t *testing.T) {
	server := newFakeServer()
	// Shutdown 一直等到 ctx 过期才返回，模拟迟迟结束不了的在途请求。
	server.shutdownDelay = time.Hour

	var hookErr error
	var hookDeadline time.Duration
	done := make(chan struct{})
	OnShutdown("hook", func(ctx context.Context) error {
		hookErr = ctx.Err()
		if deadline, ok := ctx.Deadline(); ok {
			hookDeadline = time.Until(deadline)
		}
		close(done)
		return nil
	})

	cancel, errCh := runInBackground(server, 50*time.Millisecond)
	defer cancel()
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("在途请求耗光预算后，清理钩子根本没被执行")
	}
	<-errCh

	if hookErr != nil {
		t.Fatalf("钩子拿到的 ctx 已经是 %v 状态，等于没有预算可用", hookErr)
	}
	if hookDeadline <= 0 {
		t.Fatalf("钩子剩余预算 = %v, 期望是一份新的预算", hookDeadline)
	}
}

func TestHookBudget(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "总预算充裕时给保底值", timeout: 15 * time.Second, want: defaultHookBudget},
		{name: "总预算比保底值还小就跟着缩", timeout: 2 * time.Second, want: 2 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hookBudget(c.timeout); got != c.want {
				t.Fatalf("hookBudget(%v) = %v, 期望 %v", c.timeout, got, c.want)
			}
		})
	}
}

func TestRunReportsShutdownError(t *testing.T) {
	server := newFakeServer()
	server.shutdownErr = errors.New("close listener failed")

	cancel, errCh := runInBackground(server, time.Second)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, server.shutdownErr) {
			t.Fatalf("run() = %v, 期望包住 %v", err, server.shutdownErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run 没有返回")
	}
}

func TestGetShutdownTimeoutFromConfig(t *testing.T) {
	// 对应 bee/application.yml 里的 shutdown.timeoutSeconds，改配置就能调，不用重新编译。
	if got, want := getShutdownTimeout(), 20*time.Second; got != want {
		t.Fatalf("getShutdownTimeout() = %v, 期望 %v", got, want)
	}
}

func TestHttpServerShutdownWaitsForInflightRequest(t *testing.T) {
	addr := freeAddr(t)
	server := NewHttpServer()
	released := make(chan struct{})
	entered := make(chan struct{})
	server.Get("/slow", func(ctx IContext) {
		close(entered)
		<-released
		ctx.ResponseOk(map[string]string{"ok": "1"})
	})

	runErr := make(chan error, 1)
	go func() { runErr <- server.Run(addr) }()
	waitListening(t, addr)

	respErr := make(chan error, 1)
	body := make(chan string, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/slow", addr))
		if err != nil {
			respErr <- err
			return
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		respErr <- err
		body <- string(data)
	}()
	// 等请求真的进到 handler 里再关，否则测的就不是"在途请求"了。
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("请求没有进入 handler")
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown(context.Background()) }()

	close(released)
	if err := <-respErr; err != nil {
		t.Fatalf("在途请求没有正常收尾: %v", err)
	}
	if got := <-body; got == "" {
		t.Fatal("在途请求的响应体为空，说明连接被关闭时切断了")
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown() = %v, 期望 nil", err)
	}
	// Shutdown 触发的退出不是故障，Run 必须返回 nil，否则 main 会当成启动失败。
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run() = %v, 期望 nil（ErrServerClosed 属于正常退出）", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown 之后 Run 没有返回")
	}
}

// freeAddr 先占一个随机端口再放掉，把它让给待测 server。
// ListenAndServe 只接受具体地址，拿不到 :0 实际分到的端口。
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("找空闲端口失败: %v", err)
	}
	addr := ln.Addr().String()
	if err = ln.Close(); err != nil {
		t.Fatalf("释放端口失败: %v", err)
	}
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待 %s 起监听超时", addr)
}
