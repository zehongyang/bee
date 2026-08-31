// Package lifecycle 收集进程退出前要执行的清理动作。
//
// 单独成包而不是放在 bee 根包里，是为了避免循环依赖：dbs、rds 这些子包需要在建立
// 连接时登记自己的关闭动作，而根包 bee 将来可能反过来引用它们。lifecycle 只依赖
// logger，谁都能引。
package lifecycle

import (
	"context"
	"sync"

	"github.com/zehongyang/bee/logger"
	"github.com/zehongyang/bee/utils"
)

// Hook 是一个清理动作。ctx 带着整个关闭流程共享的超时预算，耗时操作必须尊重它。
type Hook func(ctx context.Context) error

type namedHook struct {
	name string
	fn   Hook
}

var (
	mu    sync.Mutex
	hooks []namedHook
)

// OnShutdown 登记一个退出前要执行的清理动作。name 只用于日志，出问题时能看出是谁失败了。
//
// 允许重名：同一个数据库配置被不同模块各拿一次引擎是正常的，登记两条无非多打一行日志。
func OnShutdown(name string, fn Hook) {
	if fn == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	hooks = append(hooks, namedHook{name: name, fn: fn})
}

// Shutdown 按登记的相反顺序执行全部清理动作，并把登记表清空。
//
// 倒序（LIFO）是因为登记顺序天然反映依赖顺序：先有数据库连接，才有依赖它的服务。
// 关的时候反过来，被依赖的资源才不会在使用者之前消失。
//
// 单个钩子失败或 panic 都只记日志，不中断后续——退出阶段没有"回滚"可言，
// 一个钩子出问题不该让剩下的资源全都漏掉。清空登记表则保证重复调用不会执行两遍。
func Shutdown(ctx context.Context) {
	mu.Lock()
	pending := hooks
	hooks = nil
	mu.Unlock()

	for i := len(pending) - 1; i >= 0; i-- {
		runHook(ctx, pending[i])
	}
}

func runHook(ctx context.Context, h namedHook) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error().Any("err", err).Str("hook", h.name).
				Str("stack", string(utils.Stack(2))).Msg("shutdown hook panic")
		}
	}()
	if err := h.fn(ctx); err != nil {
		logger.Error().Err(err).Str("hook", h.name).Msg("shutdown hook failed")
		return
	}
	logger.Debug().Str("hook", h.name).Msg("shutdown hook done")
}
