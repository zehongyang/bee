package bee

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zehongyang/bee/config"
	"github.com/zehongyang/bee/lifecycle"
	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
)

// Server 是 bee.Run 能托管的服务：Run 阻塞式监听，Shutdown 停止接收新请求并等在途请求收尾。
// HttpServer、TcpServer、WebSocketServer 都满足它。
type Server interface {
	Run(addr string) error
	Shutdown(ctx context.Context) error
}

// ErrShutdownTimeout 表示关闭流程没能在预算内跑完，进程是被强制结束的。
var ErrShutdownTimeout = errors.New("shutdown timeout")

const (
	// defaultShutdownTimeout 是没配置 shutdown.timeoutSeconds 时的关闭预算。
	// 取 15 秒是照着编排系统的默认宽限期来的（Kubernetes 与 docker stop 都是 30 秒），
	// 留出一半余量给容器里的其他收尾动作，免得还没关完就被 SIGKILL。
	defaultShutdownTimeout = 15 * time.Second
	// forceExitGrace 是强制退出前额外等待的时间。钩子内部本该自己响应 ctx 取消，
	// 这一秒只是给它们把 ctx.Err() 转成返回值的时间，不是第二段预算。
	forceExitGrace = time.Second
	// defaultHookBudget 是留给清理钩子的独立预算。钩子干的都是关连接、删 key 这类快活，
	// 5 秒足够；给它单独一份是因为在途请求把总预算耗光是常态（比如一次几十秒的外部调用），
	// 共用的话钩子拿到手就已经是过期的 ctx——最需要清理的那次退出反而什么都清不掉。
	defaultHookBudget = 5 * time.Second
)

type shutdownConfig struct {
	Shutdown struct {
		TimeoutSeconds int
	}
}

// getShutdownTimeout 读取 application.yml 里的 shutdown.timeoutSeconds。
// 线上调这个值不该重新编译，所以走配置而不是代码常量。
var getShutdownTimeout = utils.Single(func() time.Duration {
	var sc shutdownConfig
	if err := config.Load(&sc); err != nil {
		logger.Error().Err(err).Msg("load shutdown config failed")
		return defaultShutdownTimeout
	}
	if sc.Shutdown.TimeoutSeconds <= 0 {
		return defaultShutdownTimeout
	}
	return time.Duration(sc.Shutdown.TimeoutSeconds) * time.Second
})

// OnShutdown 登记一个退出前执行的清理动作，由 Run 在关闭阶段按登记的相反顺序调用。
// dbs、rds 会自动登记各自的连接关闭，业务侧一般只需要登记自己起的后台任务。
func OnShutdown(name string, fn func(ctx context.Context) error) {
	lifecycle.OnShutdown(name, fn)
}

// Run 启动 server 并阻塞，直到收到 SIGINT/SIGTERM 或者 server 自己退出。
//
// 收到信号后的顺序是固定的：先让 server 停止接受新请求并等在途请求结束，再倒序执行
// OnShutdown 登记的清理动作，两段共用一份超时预算。没有这一层的话，进程只能被信号
// 直接打死——在途请求当场断连，数据库连接也来不及归还。
func Run(server Server, addr string) error {
	// NotifyContext 而不是自己开 channel：stop() 能把信号处理还原成默认行为，
	// 这样关闭卡住时用户再按一次 Ctrl+C 就能立刻杀掉进程，不至于干等。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, stop, server, addr, getShutdownTimeout())
}

// run 是 Run 去掉信号监听之后的主体。抽出来是为了让测试能用一个普通的可取消 ctx
// 驱动整个关闭流程——Windows 上没法给自己发 SIGTERM，测不了真信号。
func run(ctx context.Context, stop func(), server Server, addr string, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(addr)
	}()

	select {
	case err := <-errCh:
		// 监听没起来（端口被占）或者服务自己退了。这时 handler 工厂可能已经建好了
		// 数据库和 Redis 连接，所以钩子照跑，不能直接返回把连接留给进程退出去硬切。
		runHooks(timeout)
		if err != nil {
			return fmt.Errorf("run server: %w", err)
		}
		return nil
	case <-ctx.Done():
	}
	stop()
	logger.Info().Dur("timeout", timeout).Msg("signal received, shutting down")

	hooks := hookBudget(timeout)
	sctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		err := server.Shutdown(sctx)
		// 服务没停干净也要继续释放资源：连接池、文件句柄不会因为 Shutdown 失败就不用关。
		hctx, hcancel := context.WithTimeout(context.Background(), hooks)
		defer hcancel()
		lifecycle.Shutdown(hctx)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		logger.Info().Msg("shutdown completed")
		return nil
	case <-time.After(timeout + hooks + forceExitGrace):
		// 兜底：有钩子不理会 ctx 时，宁可丢掉没跑完的清理也要退出。
		// 挂着不退只会让编排系统在宽限期结束后 SIGKILL，结果更糟。
		logger.Error().Dur("timeout", timeout).Msg("graceful shutdown timeout, force exit")
		return ErrShutdownTimeout
	}
}

// hookBudget 算出留给清理钩子的预算。总预算比保底值还小时跟着缩，
// 免得配了个 2 秒的关闭超时，实际却要等上 7 秒。
func hookBudget(timeout time.Duration) time.Duration {
	if timeout < defaultHookBudget {
		return timeout
	}
	return defaultHookBudget
}

// runHooks 在没有走完整关闭流程时单独跑一遍清理钩子。
func runHooks(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	lifecycle.Shutdown(ctx)
}
