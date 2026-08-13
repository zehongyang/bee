package authtoken

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/zehongyang/bee"
)

// TestStoreKeyIsolatesNamespaces 验证不同命名空间的同一个 token 落在不同的 Redis key 上。
//
// 这就是隔离两套登录态的全部机制：一边签发的 token 在另一边根本查不到。
// 如果这两个 key 相同，管理后台就会接受普通用户的 token——
// 因为 Verify 只能返回 uid，分辨不出这个 uid 是用户还是管理员。
func TestStoreKeyIsolatesNamespaces(t *testing.T) {
	const token = "sametoken"
	app := New("default", "")
	admin := New("default", "admin")

	if app.key(token) == admin.key(token) {
		t.Fatalf("两个命名空间必须落在不同的 key 上，都是 %q", app.key(token))
	}
}

// TestStoreDefaultKeyMatchesLegacy 验证空命名空间生成的 key 与包级函数完全一致。
//
// 这是一条兼容性回归：线上已经有用包级 Issue 签发、还没过期的 token（有效期 30 天）。
// 空命名空间要是换了 key 格式，那些 token 会在发版当天集体失效，所有人被登出。
func TestStoreDefaultKeyMatchesLegacy(t *testing.T) {
	const token = "abc123"
	got := New("default", "").key(token)
	want := keyPrefix + token
	if got != want {
		t.Fatalf("默认命名空间的 key = %q，与包级函数的 %q 不一致", got, want)
	}
}

// TestStoreNamespacedKeyFormat 验证带命名空间时的 key 格式，防止以后有人改动分隔符
// 导致已签发的 token 全部失效。
func TestStoreNamespacedKeyFormat(t *testing.T) {
	got := New("default", "admin").key("abc123")
	want := keyPrefix + "admin:abc123"
	if got != want {
		t.Fatalf("带命名空间的 key = %q, want %q", got, want)
	}
}

// TestStoreVerifyRejectsEmptyToken 验证空 token 直接被拒，不会去连 Redis。
func TestStoreVerifyRejectsEmptyToken(t *testing.T) {
	if _, err := New("default", "admin").Verify(""); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for an empty token, got %v", err)
	}
}

// TestStoreRevokeEmptyTokenIsNoop 验证登出一个空 token 视为成功，登出接口应当幂等。
func TestStoreRevokeEmptyTokenIsNoop(t *testing.T) {
	if err := New("default", "admin").Revoke(""); err != nil {
		t.Fatalf("expected revoking an empty token to be a no-op, got %v", err)
	}
}

// TestStoreMiddlewareUsesCustomCode 验证命名空间中间件能返回自己的错误码。
//
// 一个进程里同时跑着 App 和管理后台两套登录态，前端要靠错误码区分
// "跳 App 登录页"还是"跳后台登录页"，两者不能共用一个码。
func TestStoreMiddlewareUsesCustomCode(t *testing.T) {
	const adminCode = 6001
	server := bee.NewHttpServer()
	var handlerCalled bool
	group := server.Group("/api/v1/admin")
	group.Use(New("default", "admin").Middleware(adminCode, "后台登录状态已失效"))
	group.Get("/users", func(ctx bee.IContext) {
		handlerCalled = true
		ctx.ResponseOk(nil)
	})

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil))

	if handlerCalled {
		t.Fatalf("没有登录态时不该执行后面的 handler")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("按框架约定 HTTP 状态码恒为 200，got %d", recorder.Code)
	}
	if got := recorder.Header().Get(bee.HeaderCode); got != strconv.Itoa(adminCode) {
		t.Fatalf("Code 响应头 = %q, want %q", got, strconv.Itoa(adminCode))
	}
}
