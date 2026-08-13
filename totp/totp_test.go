package totp

import (
	"strings"
	"testing"
	"time"
)

// rfcSecret 是 RFC 6238 附录 B 用的种子 "12345678901234567890" 的 base32 形式。
// 官方向量是按 ASCII 种子给的，这里转成本包接受的 base32。
var rfcSecret = encoding.EncodeToString([]byte("12345678901234567890"))

// TestCodeMatchesRFC6238Vectors 用 RFC 6238 附录 B 的官方测试向量验证算法实现。
//
// 自己实现密码算法最大的风险不是写不出来，而是写出一个"看着能用、和别人对不上"的版本——
// 那样用户拿 Google Authenticator 扫了码却永远登不进去。官方向量是唯一能证伪这件事的东西。
// 向量是 8 位的，所以这里按 8 位算。
func TestCodeMatchesRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{unix: 59, want: "94287082"},
		{unix: 1111111109, want: "07081804"},
		{unix: 1111111111, want: "14050471"},
		{unix: 1234567890, want: "89005924"},
		{unix: 2000000000, want: "69279037"},
		{unix: 20000000000, want: "65353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0).UTC(), 8)
		if err != nil {
			t.Fatalf("Code() error: %v", err)
		}
		if got != c.want {
			t.Fatalf("Code(t=%d) = %q, want %q", c.unix, got, c.want)
		}
	}
}

// TestCodeDefaultsToSixDigits 验证不指定位数时给出 6 位密码，与通用验证器的显示一致。
func TestCodeDefaultsToSixDigits(t *testing.T) {
	got, err := Code(rfcSecret, time.Unix(59, 0).UTC(), 0)
	if err != nil {
		t.Fatalf("Code() error: %v", err)
	}
	if len(got) != Digits {
		t.Fatalf("expected %d digits, got %q", Digits, got)
	}
	// 6 位就是 8 位向量的后 6 位。
	if got != "287082" {
		t.Fatalf("Code() = %q, want %q", got, "287082")
	}
}

// TestCodeIsStableWithinPeriod 验证同一个时间步内密码不变，跨步之后改变。
func TestCodeIsStableWithinPeriod(t *testing.T) {
	base := time.Unix(1111111111, 0).UTC()

	first, _ := Code(rfcSecret, base, Digits)
	// 同一个 30 秒窗口内的另一个时刻。
	same, _ := Code(rfcSecret, base.Add(5*time.Second), Digits)
	if first != same {
		t.Fatalf("同一时间步内密码应保持不变，got %q 和 %q", first, same)
	}

	next, _ := Code(rfcSecret, base.Add(Period), Digits)
	if first == next {
		t.Fatalf("跨过一个时间步之后密码应当改变，仍是 %q", first)
	}
}

// TestValidateAcceptsClockSkew 验证 ±1 个时间步的容错。
//
// 手机和服务器差个几十秒很常见，一点容错都不留会让相当一部分用户莫名其妙登不进来。
func TestValidateAcceptsClockSkew(t *testing.T) {
	now := time.Unix(1111111111, 0).UTC()
	previous, _ := Code(rfcSecret, now.Add(-Period), Digits)
	next, _ := Code(rfcSecret, now.Add(Period), Digits)

	if _, ok := Validate(rfcSecret, previous, now, 1); !ok {
		t.Fatalf("上一个时间步的密码应当被接受")
	}
	if _, ok := Validate(rfcSecret, next, now, 1); !ok {
		t.Fatalf("下一个时间步的密码应当被接受")
	}
	// skew=0 时只认当前这一步。
	if _, ok := Validate(rfcSecret, previous, now, 0); ok {
		t.Fatalf("skew=0 时不该接受上一个时间步的密码")
	}
}

// TestValidateRejectsOutOfWindow 验证窗口之外的密码会被拒。
//
// 窗口每放宽一步，同一个密码的可用时长就多 30 秒，所以边界必须是硬的。
func TestValidateRejectsOutOfWindow(t *testing.T) {
	now := time.Unix(1111111111, 0).UTC()
	stale, _ := Code(rfcSecret, now.Add(-3*Period), Digits)

	if _, ok := Validate(rfcSecret, stale, now, 1); ok {
		t.Fatalf("三个时间步之前的密码不该在 skew=1 时被接受")
	}
}

// TestValidateReturnsStepForReplayGuard 验证校验成功时返回命中的时间步。
//
// 本包不负责防重放，但必须把"用的是哪一步"告诉调用方，
// 否则调用方无从记录"这个密码已经用过了"，密码被旁窥后 30 秒内可以重复使用。
func TestValidateReturnsStepForReplayGuard(t *testing.T) {
	now := time.Unix(1111111111, 0).UTC()
	code, _ := Code(rfcSecret, now, Digits)

	step, ok := Validate(rfcSecret, code, now, 1)
	if !ok {
		t.Fatalf("expected the current code to validate")
	}
	wantStep := now.Unix() / int64(Period.Seconds())
	if step != wantStep {
		t.Fatalf("returned step = %d, want %d", step, wantStep)
	}

	// 上一步的密码要返回上一步的编号，否则防重放会记错格子。
	previous, _ := Code(rfcSecret, now.Add(-Period), Digits)
	step, ok = Validate(rfcSecret, previous, now, 1)
	if !ok || step != wantStep-1 {
		t.Fatalf("上一个时间步的密码应返回 step=%d，got %d (ok=%v)", wantStep-1, step, ok)
	}
}

// TestValidateRejectsEmptyAndWrongCode 验证空密码和错误密码都会被拒。
func TestValidateRejectsEmptyAndWrongCode(t *testing.T) {
	now := time.Unix(1111111111, 0).UTC()
	for _, code := range []string{"", "   ", "000000", "abcdef"} {
		if _, ok := Validate(rfcSecret, code, now, 1); ok {
			t.Fatalf("code %q 不该通过校验", code)
		}
	}
}

// TestGenerateSecretIsUsable 验证生成的密钥能直接拿来算密码，且两次生成不重复。
func TestGenerateSecretIsUsable(t *testing.T) {
	first, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error: %v", err)
	}
	second, _ := GenerateSecret()
	if first == second {
		t.Fatalf("两次生成的密钥不该相同")
	}
	if strings.Contains(first, "=") {
		t.Fatalf("密钥不该带 padding，验证器普遍不接受：%q", first)
	}

	code, err := Code(first, time.Now(), Digits)
	if err != nil {
		t.Fatalf("新生成的密钥应当可用: %v", err)
	}
	if len(code) != Digits {
		t.Fatalf("expected %d digits, got %q", Digits, code)
	}
}

// TestDecodeSecretTolerates 验证手工输入密钥时的常见写法都能被接受：小写、空格、padding。
func TestDecodeSecretTolerates(t *testing.T) {
	now := time.Unix(59, 0).UTC()
	want, _ := Code(rfcSecret, now, Digits)

	variants := []string{
		strings.ToLower(rfcSecret),
		rfcSecret[:4] + " " + rfcSecret[4:],
		rfcSecret + "======",
	}
	for _, variant := range variants {
		got, err := Code(variant, now, Digits)
		if err != nil {
			t.Fatalf("变体 %q 应当可用: %v", variant, err)
		}
		if got != want {
			t.Fatalf("变体 %q 算出 %q，与规范写法的 %q 不一致", variant, got, want)
		}
	}
}

// TestDecodeSecretRejectsGarbage 验证非法密钥会报错而不是算出一个看着正常的密码。
func TestDecodeSecretRejectsGarbage(t *testing.T) {
	for _, secret := range []string{"", "   ", "not-base32!"} {
		if _, err := Code(secret, time.Now(), Digits); err == nil {
			t.Fatalf("secret %q 应当被拒", secret)
		}
	}
}

// TestProvisioningURI 验证 otpauth 链接的关键参数，扫码绑定全靠它。
func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("MeetPro", "admin", "ABCDEFGH")

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("otpauth 链接前缀不对: %s", uri)
	}
	for _, fragment := range []string{"secret=ABCDEFGH", "issuer=MeetPro", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, fragment) {
			t.Fatalf("链接里缺少 %q: %s", fragment, uri)
		}
	}
	if !strings.Contains(uri, "MeetPro:admin") {
		t.Fatalf("链接里应含 issuer:account 标签: %s", uri)
	}
}
