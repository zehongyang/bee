package authtoken

import "testing"

// TestRandomTokenUniqueAndLength 验证生成的 token 是 64 位十六进制字符串（32 字节），且两次生成不会重复，
// 避免以后有人把随机源改小导致 token 变得可猜测。
func TestRandomTokenUniqueAndLength(t *testing.T) {
	a, err := randomToken()
	if err != nil {
		t.Fatalf("randomToken() error: %v", err)
	}
	b, err := randomToken()
	if err != nil {
		t.Fatalf("randomToken() error: %v", err)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars (32 bytes), got %d: %s", len(a), a)
	}
	if a == b {
		t.Fatalf("expected two random tokens to differ, both are %s", a)
	}
}
