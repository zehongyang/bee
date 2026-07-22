package bee

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRecoveryStopsChainAfterPanic 验证 Recovery 捕获某个中间件的 panic 后：
// 1) 不会导致进程崩溃，返回统一的 internal_error 响应；
// 2) 链路上位于 panic 之后的 handler（这里是路由最终 handler）不会被继续执行。
// 这是回归测试：如果只是不调用 ctx.Next() 而不显式 Abort，gin 的调用链循环会继续执行后面的 handler。
func TestRecoveryStopsChainAfterPanic(t *testing.T) {
	server := NewHttpServer()
	var finalHandlerCalled bool
	server.Use(Recovery())
	server.Use(func(ctx IContext) {
		panic("boom")
	})
	server.Get("/panic", func(ctx IContext) {
		finalHandlerCalled = true
		RespondOK(ctx, nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()
	server.engine.ServeHTTP(w, req)

	if finalHandlerCalled {
		t.Fatalf("expected route handler after the panicking middleware not to run, but it was called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected http status 200 per bee envelope convention, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("expected body to contain internal_error code, got %s", w.Body.String())
	}
}

// TestRequestIDReusesIncomingHeader 验证 RequestID 中间件优先复用调用方传入的请求头，而不是每次都重新生成。
func TestRequestIDReusesIncomingHeader(t *testing.T) {
	server := NewHttpServer()
	server.Use(RequestID())
	server.Get("/ping", func(ctx IContext) {
		RespondOK(ctx, map[string]string{"msg": "pong"})
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set(RequestIDHeader, "fixed-request-id")
	w := httptest.NewRecorder()
	server.engine.ServeHTTP(w, req)

	if got := w.Header().Get(RequestIDHeader); got != "fixed-request-id" {
		t.Fatalf("expected request id to be reused as fixed-request-id, got %s", got)
	}
	if !strings.Contains(w.Body.String(), "fixed-request-id") {
		t.Fatalf("expected response body to carry the same request_id, got %s", w.Body.String())
	}
}
