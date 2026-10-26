package bee

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSetTrustedProxies 验证 GetIp 只采信可信代理转发来的 X-Forwarded-For。
//
// gin.Default() 默认谁都信，客户端自己带一个 X-Forwarded-For 就能冒充任意 IP，
// 按 IP 的限流和白名单形同虚设。这里把"不信陌生来源、只信配置的代理"钉住。
func TestSetTrustedProxies(t *testing.T) {
	cases := []struct {
		name       string
		proxies    []string
		remoteAddr string
		want       string
	}{
		{name: "不配置代理时忽略伪造的头", proxies: nil, remoteAddr: "203.0.113.7:5000", want: "203.0.113.7"},
		{name: "来源不是可信代理时忽略", proxies: []string{"127.0.0.1"}, remoteAddr: "203.0.113.7:5000", want: "203.0.113.7"},
		{name: "来自可信代理时采信", proxies: []string{"127.0.0.1"}, remoteAddr: "127.0.0.1:5000", want: "198.51.100.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := NewHttpServer()
			if err := server.SetTrustedProxies(c.proxies); err != nil {
				t.Fatalf("SetTrustedProxies failed: %v", err)
			}
			var got string
			server.Get("/ip", func(ctx IContext) {
				got = ctx.GetIp()
				ctx.ResponseOk(nil)
			})
			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			req.RemoteAddr = c.remoteAddr
			req.Header.Set("X-Forwarded-For", "198.51.100.9")
			server.ServeHTTP(httptest.NewRecorder(), req)
			if got != c.want {
				t.Fatalf("GetIp() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSetTrustedProxiesRejectsInvalid 验证写错的代理地址在启动时就报错，而不是静默地谁都不信或谁都信。
func TestSetTrustedProxiesRejectsInvalid(t *testing.T) {
	if err := NewHttpServer().SetTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid proxy address")
	}
}
