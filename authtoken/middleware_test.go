package authtoken

import "testing"

// TestExtractToken 验证从 Authorization 请求头里解析 token 时，
// 能正确剥离 "Bearer " 前缀，也能兼容调用方直接传裸 token 的情况。
func TestExtractToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{name: "空请求头", header: "", want: ""},
		{name: "带Bearer前缀", header: "Bearer abc123", want: "abc123"},
		{name: "裸token", header: "abc123", want: "abc123"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractToken(c.header)
			if got != c.want {
				t.Fatalf("extractToken(%q) = %q, want %q", c.header, got, c.want)
			}
		})
	}
}
