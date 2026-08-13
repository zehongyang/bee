// Package totp 实现 RFC 6238 定义的基于时间的一次性密码（TOTP），
// 用于给管理后台这类高权限入口加一道二次验证。
//
// 只用标准库：算法本身就是 HMAC-SHA1 加一个时间步计数器，几十行的事，
// 引一个第三方库反而多一份要跟进的依赖。生成的密码与 Google Authenticator、
// 微软 Authenticator、1Password 等通用验证器完全兼容。
//
// 注意：本包只负责算出和校验密码，**不负责防重放**。同一个密码在它的有效窗口内
// 算出来永远是对的，调用方必须自己记住"这个时间步已经用过了"（例如写进 Redis），
// 否则密码被旁窥之后 30 秒内可以被重复使用。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period 是时间步长，RFC 6238 推荐 30 秒，通用验证器也都按这个实现。
	Period = 30 * time.Second
	// Digits 是密码位数，通用验证器一律显示 6 位。
	Digits = 6
	// SecretBytes 是生成密钥的字节数。20 字节即 160 位，与 RFC 4226 对 HMAC-SHA1 的建议一致。
	SecretBytes = 20
)

// ErrInvalidSecret 表示密钥不是合法的 base32 字符串。
var ErrInvalidSecret = errors.New("invalid totp secret")

// encoding 是不带 padding 的标准 base32。
//
// 验证器普遍不接受 '=' 填充，带上会导致用户手工输入密钥时被拒。
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成一个新的随机密钥，返回可以直接展示给用户的 base32 字符串。
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return encoding.EncodeToString(buf), nil
}

// Code 按给定时刻算出密码。
//
// 时间步计数器 = Unix 秒 / 30，取 HMAC-SHA1 结果做 RFC 4226 的动态截断，
// 再对 10^digits 取模。
func Code(secret string, at time.Time, digits int) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	if digits <= 0 {
		digits = Digits
	}

	counter := uint64(at.Unix()) / uint64(Period.Seconds())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// 动态截断：用最后一个字节的低 4 位当偏移，从那里取 4 字节，抹掉最高位避免符号问题。
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod), nil
}

// Validate 校验密码是否正确，并返回它命中的时间步。
//
// skew 是允许的前后时间步偏移，传 1 表示接受前后各 30 秒——手机和服务器的时钟
// 差个几十秒很常见，一点容错都不留会让相当一部分用户莫名其妙登不进来。
// 但也不能给太大：窗口每放宽一步，同一个密码的可用时长就多 30 秒。
//
// 返回的时间步是给调用方做防重放用的：把它记下来，同一个时间步再来就拒掉。
func Validate(secret, code string, at time.Time, skew int) (int64, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}
	if skew < 0 {
		skew = 0
	}

	step := int64(Period.Seconds())
	for offset := -skew; offset <= skew; offset++ {
		moment := at.Add(time.Duration(offset) * Period)
		expected, err := Code(secret, moment, len(code))
		if err != nil {
			return 0, false
		}
		// 定长比较用 hmac.Equal 走常数时间，不给计时攻击留侧信道。
		if hmac.Equal([]byte(expected), []byte(code)) {
			return moment.Unix() / step, true
		}
	}
	return 0, false
}

// ProvisioningURI 生成 otpauth:// 链接，供前端渲染成二维码让用户扫码绑定。
//
// 刻意不在这里生成二维码图片：那需要引入一个画图的依赖，而前端本来就有现成的
// 二维码组件，服务端只出这一行字符串就够了。
func ProvisioningURI(issuer, account, secret string) string {
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	query := url.Values{}
	query.Set("secret", secret)
	if issuer != "" {
		query.Set("issuer", issuer)
	}
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", Digits))
	query.Set("period", fmt.Sprintf("%d", int(Period.Seconds())))

	return "otpauth://totp/" + url.PathEscape(label) + "?" + query.Encode()
}

// decodeSecret 把 base32 密钥解回原始字节，兼容用户手工输入时带上的空格和小写。
func decodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	if normalized == "" {
		return nil, ErrInvalidSecret
	}
	key, err := encoding.DecodeString(normalized)
	if err != nil {
		return nil, ErrInvalidSecret
	}
	return key, nil
}
