package third

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// QiniuCredentials 是七牛云的一对密钥，用来给私有空间的资源签发限时下载地址。
//
// 只做下载签名，不做上传凭证：上传发生在我们自己的机器上（打好模型包手动传），
// 服务端没有任何理由持有一个能往空间里写东西的能力。
//
// SecretKey 绝不能出现在日志、响应体或任何对外结构里——它等价于整个空间的控制权。
type QiniuCredentials struct {
	accessKey string
	secretKey string
}

// ErrQiniuCredentialsMissing 表示密钥没配全。
//
// 单独一个错误而不是直接签出一个空 token：带着半套密钥去签，签出来的地址
// 一定是 401，而那会被当成"七牛挂了"排查很久，不如在这里就说清楚是配置问题。
var ErrQiniuCredentialsMissing = errors.New("qiniu: accessKey 或 secretKey 为空")

// ErrQiniuDomainMissing 表示下载域名为空。
var ErrQiniuDomainMissing = errors.New("qiniu: domain 为空")

// NewQiniuCredentials 构造一对七牛密钥。
func NewQiniuCredentials(accessKey, secretKey string) *QiniuCredentials {
	return &QiniuCredentials{accessKey: accessKey, secretKey: secretKey}
}

// SignDownloadURL 给私有空间里的 key 签一个在 expiresAt 之前有效的下载地址。
//
// 七牛的私有下载凭证算法（官方文档「下载凭证」一节）：
//
//	urlToSign = <domain>/<key>?e=<deadline 秒级时间戳>
//	token     = <accessKey>:<urlsafe-base64(HMAC-SHA1(secretKey, urlToSign))>
//	下载地址  = urlToSign&token=<token>
//
// 三件必须注意的事：
//
//  1. **参与签名的是完整 URL，scheme 也在里面。** 拿 http 的地址签出来的 token，
//     换成 https 去请求一定是 401，反之亦然。domain 配成什么协议，客户端就只能用什么协议。
//  2. **key 要做路径转义，但不能转义斜杠。** 七牛的 key 允许带 `/`，它在 URL 里是路径分隔符，
//     被转义成 %2F 就变成了另一个 key。
//  3. **domain 已经带 query 时用 & 而不是 ?**。我们自己不会这么用，但这个函数是通用能力，
//     不该在被别处复用时悄悄签出一个畸形地址。
//
// 刻意不接受"有效期时长"而接受一个绝对时间点：调用方通常要把同一个过期时间
// 一并返回给客户端（好让客户端知道什么时候该重新要一个），传时长的话
// 这里算出来的 deadline 和调用方自己算的可能差上几毫秒，跨天或临界时会对不上。
func (c *QiniuCredentials) SignDownloadURL(domain, key string, expiresAt time.Time) (string, error) {
	if c == nil || c.accessKey == "" || c.secretKey == "" {
		return "", ErrQiniuCredentialsMissing
	}
	domain = strings.TrimRight(domain, "/")
	if domain == "" {
		return "", ErrQiniuDomainMissing
	}

	separator := "?"
	if strings.Contains(domain, "?") {
		separator = "&"
	}
	urlToSign := domain + "/" + escapeKey(key) +
		separator + "e=" + strconv.FormatInt(expiresAt.Unix(), 10)

	mac := hmac.New(sha1.New, []byte(c.secretKey))
	// hash.Hash 的 Write 契约上永远返回 nil error，所以这里不做错误处理。
	mac.Write([]byte(urlToSign))
	sign := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return urlToSign + "&token=" + c.accessKey + ":" + sign, nil
}

// escapeKey 把 key 转义成能放进 URL 路径的形式，斜杠保持原样（它是目录分隔符）。
//
// url.PathEscape 会把 `/` 转成 %2F，所以按段转义再拼回去。
func escapeKey(key string) string {
	segments := strings.Split(key, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}
