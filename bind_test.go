package bee

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestBindFailureLeavesResponseToCaller 验证 Bind 解析失败时不自己写响应，
// 调用方随后的 ResponseError 能完整发出：HTTP 200 + Code 头 + Error 头。
//
// 这是回归测试：Bind 以前直接调 gin 的 Bind，解析失败会立刻写出 HTTP 400，
// 之后 ResponseError 设置的头全部丢失，客户端收到一个没有 Code 头的 400。
// 必须用真实的 HTTP 连接测：httptest.ResponseRecorder 的 Header() 在状态行写出之后仍然可改，
// 会把“其实没发出去”的头也显示出来。
func TestBindFailureLeavesResponseToCaller(t *testing.T) {
	server := NewHttpServer()
	server.Post("/bind", func(ctx IContext) {
		var obj struct {
			Name string `json:"name"`
		}
		if err := ctx.Bind(&obj); err != nil {
			ctx.ResponseError(1001, "请求体不是合法的 JSON")
			return
		}
		ctx.ResponseOk(obj)
	})
	ts := httptest.NewServer(server)
	defer ts.Close()

	cases := []struct {
		name     string
		body     string
		wantCode string
		wantErr  string
		wantBody string
	}{
		{name: "坏 JSON", body: `{"name":`, wantCode: "1001", wantErr: "请求体不是合法的 JSON"},
		{name: "类型不对", body: `{"name":1}`, wantCode: "1001", wantErr: "请求体不是合法的 JSON"},
		{name: "正常", body: `{"name":"bee"}`, wantCode: "200", wantBody: `{"name":"bee"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/bind", "application/json", strings.NewReader(c.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected http status 200, got %d", resp.StatusCode)
			}
			if got := resp.Header.Get(HeaderCode); got != c.wantCode {
				t.Fatalf("expected Code header %q, got %q", c.wantCode, got)
			}
			if c.wantErr != "" {
				msg, _ := url.QueryUnescape(resp.Header.Get(HeaderError))
				if msg != c.wantErr {
					t.Fatalf("expected Error header %q, got %q", c.wantErr, msg)
				}
			}
			if string(body) != c.wantBody {
				t.Fatalf("expected body %q, got %q", c.wantBody, body)
			}
		})
	}
}
