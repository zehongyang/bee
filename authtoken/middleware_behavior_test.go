package authtoken

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zehongyang/bee"
)

// TestMiddlewareRejectsWithCodeHeader 验证登录态校验失败时：
// 1) HTTP 状态码仍然是 200（本框架不依赖传输层状态码表达业务结果）；
// 2) 错误码写在 Code 响应头里，取值来自可配置的 UnauthenticatedCode；
// 3) 后续 handler 不会被执行。
//
// 第三点是回归测试：中间件里只要不调用 Next() 并不能阻止 gin 继续跑后面的 handler，
// 必须真正中断调用链，否则未登录的请求会照样打到业务逻辑上。
func TestMiddlewareRejectsWithCodeHeader(t *testing.T) {
	original := UnauthenticatedCode
	UnauthenticatedCode = 2001
	t.Cleanup(func() { UnauthenticatedCode = original })

	server := bee.NewHttpServer()
	var handlerCalled bool
	group := server.Group("/api")
	group.Use(Middleware("default"))
	group.Get("/me", func(ctx bee.IContext) {
		handlerCalled = true
		ctx.ResponseOk(map[string]string{"ok": "yes"})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if handlerCalled {
		t.Fatalf("expected the protected handler not to run without a valid token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected http status 200 per framework convention, got %d", w.Code)
	}
	if got := w.Header().Get(bee.HeaderCode); got != "2001" {
		t.Fatalf("expected Code header to carry the configured error code, got %q", got)
	}
	if w.Header().Get(bee.HeaderError) == "" {
		t.Fatalf("expected Error header to carry a message")
	}
}
