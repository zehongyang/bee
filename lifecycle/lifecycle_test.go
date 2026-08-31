package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// reset 清掉登记表，避免用例之间互相干扰（Shutdown 本身也会清，但失败的用例可能没跑到）。
func reset() {
	mu.Lock()
	hooks = nil
	mu.Unlock()
}

func TestShutdownRunsHooksInReverseOrder(t *testing.T) {
	reset()
	var got []string
	for _, name := range []string{"db", "redis", "worker"} {
		OnShutdown(name, func(ctx context.Context) error {
			got = append(got, name)
			return nil
		})
	}

	Shutdown(context.Background())

	want := []string{"worker", "redis", "db"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("执行顺序 = %v, 期望 %v（必须倒序，后登记的先关）", got, want)
	}
}

func TestShutdownKeepsGoingOnFailure(t *testing.T) {
	cases := []struct {
		name string
		bad  Hook
	}{
		{name: "返回错误", bad: func(ctx context.Context) error { return errors.New("boom") }},
		{name: "直接 panic", bad: func(ctx context.Context) error { panic("boom") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset()
			var ran []string
			OnShutdown("first", func(ctx context.Context) error {
				ran = append(ran, "first")
				return nil
			})
			OnShutdown("bad", c.bad)
			OnShutdown("last", func(ctx context.Context) error {
				ran = append(ran, "last")
				return nil
			})

			Shutdown(context.Background())

			// 坏钩子夹在中间，它前后登记的都必须照跑：退出阶段没有回滚可言，
			// 一个钩子出问题不该让其余资源全漏掉。
			if want := []string{"last", "first"}; !reflect.DeepEqual(ran, want) {
				t.Fatalf("执行到的钩子 = %v, 期望 %v", ran, want)
			}
		})
	}
}

func TestShutdownOnlyRunsEachHookOnce(t *testing.T) {
	reset()
	var count int
	OnShutdown("db", func(ctx context.Context) error {
		count++
		return nil
	})

	Shutdown(context.Background())
	Shutdown(context.Background())

	if count != 1 {
		t.Fatalf("钩子执行次数 = %d, 期望 1（重复调用 Shutdown 不能关第二遍）", count)
	}
}

func TestShutdownPassesContextToHook(t *testing.T) {
	reset()
	var deadlineOK bool
	OnShutdown("db", func(ctx context.Context) error {
		_, deadlineOK = ctx.Deadline()
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	Shutdown(ctx)

	if !deadlineOK {
		t.Fatal("钩子拿到的 ctx 没有 deadline，耗时清理动作就失去了超时预算")
	}
}

func TestOnShutdownIgnoresNil(t *testing.T) {
	reset()
	OnShutdown("nil", nil)
	// 不 panic 即通过：登记 nil 多半是调用方的疏忽，不值得让进程在退出时才炸。
	Shutdown(context.Background())
}
