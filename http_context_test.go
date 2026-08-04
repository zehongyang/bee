package bee

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHttpContextQuery 验证 IContext.Query 能读到 URL 查询参数，且参数缺失时返回空字符串。
//
// 这是回归测试：加这个方法之前，IContext 完全没有读查询参数的能力，
// 业务侧只能退而用 gin 的 Bind——而 Bind 解析失败会直接写出 HTTP 400 并中断请求，
// 破坏"业务错误一律 200 + 响应体 error 字段"的统一约定（见 envelope.go）。
func TestHttpContextQuery(t *testing.T) {
	cases := []struct {
		name string
		url  string
		key  string
		want string
	}{
		{name: "读到已有参数", url: "/list?after_id=42&limit=20", key: "after_id", want: "42"},
		{name: "读到第二个参数", url: "/list?after_id=42&limit=20", key: "limit", want: "20"},
		{name: "参数不存在返回空串", url: "/list?after_id=42", key: "limit", want: ""},
		{name: "没有查询串返回空串", url: "/list", key: "after_id", want: ""},
		{name: "参数存在但为空", url: "/list?after_id=", key: "after_id", want: ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := NewHttpServer()
			var got string
			server.Get("/list", func(ctx IContext) {
				got = ctx.Query(c.key)
				RespondOK(ctx, nil)
			})

			req := httptest.NewRequest(http.MethodGet, c.url, nil)
			w := httptest.NewRecorder()
			server.engine.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected http status 200, got %d", w.Code)
			}
			if got != c.want {
				t.Fatalf("expected query value %q, got %q", c.want, got)
			}
		})
	}
}
