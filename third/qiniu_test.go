package third

import (
	"errors"
	"testing"
	"time"
)

// 期望值由一份**独立实现**（Python 的 hmac + base64.urlsafe_b64encode）算出，
// 不是拿本文件的代码自己生成的——自己验自己只能证明"两次跑出来一样"，
// 证明不了算法和七牛对得上。算法本身另外用真实空间做过一次联调：
// 签出来的地址返回 206，去掉 token 返回 401。
const (
	testAccessKey = "MY_ACCESS_KEY"
	testSecretKey = "MY_SECRET_KEY"
	testDeadline  = 1767225600
)

func TestSignDownloadURL(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		key    string
		want   string
	}{
		{
			name:   "普通 key",
			domain: "http://model.example.com",
			key:    "models/archive.zip",
			want: "http://model.example.com/models/archive.zip?e=1767225600" +
				"&token=MY_ACCESS_KEY:xP_Irxz13uLYMTurKDKm623DYpE=",
		},
		{
			// 空格要转义，斜杠必须保持原样——它是目录分隔符，转成 %2F 就指向
			// 另一个 key 了。`+` 在 URL **路径**里就是一个加号（只有 query 里才代表空格），
			// 按 RFC 3986 不需要转义，所以原样留着。
			name:   "key 需要转义但斜杠保持原样",
			domain: "http://model.example.com",
			key:    "a b/c+d.zip",
			want: "http://model.example.com/a%20b/c+d.zip?e=1767225600" +
				"&token=MY_ACCESS_KEY:8jBJTepULecoSlLEouk2a3BS_D0=",
		},
		{
			// 域名末尾多一个斜杠是配置里最常见的手误，不能因此签出 //key。
			name:   "域名末尾的斜杠被吃掉",
			domain: "http://model.example.com/",
			key:    "models/archive.zip",
			want: "http://model.example.com/models/archive.zip?e=1767225600" +
				"&token=MY_ACCESS_KEY:xP_Irxz13uLYMTurKDKm623DYpE=",
		},
	}

	credentials := NewQiniuCredentials(testAccessKey, testSecretKey)
	expiresAt := time.Unix(testDeadline, 0)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := credentials.SignDownloadURL(c.domain, c.key, expiresAt)
			if err != nil {
				t.Fatalf("SignDownloadURL 返回错误: %v", err)
			}
			if got != c.want {
				t.Fatalf("签名地址不一致\n got: %s\nwant: %s", got, c.want)
			}
		})
	}
}

// 换一个 scheme 必须得到完全不同的 token：参与签名的是整个 URL，
// 协议也在里面。拿 http 的 token 去请求 https 地址只会得到 401，
// 所以配置里的域名协议和客户端实际请求的协议必须一致。
func TestSignDownloadURLSchemeIsPartOfSignature(t *testing.T) {
	credentials := NewQiniuCredentials(testAccessKey, testSecretKey)
	expiresAt := time.Unix(testDeadline, 0)

	plain, err := credentials.SignDownloadURL("http://model.example.com", "a.zip", expiresAt)
	if err != nil {
		t.Fatalf("签名 http 地址失败: %v", err)
	}
	secure, err := credentials.SignDownloadURL("https://model.example.com", "a.zip", expiresAt)
	if err != nil {
		t.Fatalf("签名 https 地址失败: %v", err)
	}
	if plain[len("http"):] == secure[len("https"):] {
		t.Fatal("http 与 https 签出了同一个 token，说明 scheme 没进签名")
	}
}

// 过期时间不同必须签出不同的 token，否则"限时"就是假的。
func TestSignDownloadURLDeadlineIsPartOfSignature(t *testing.T) {
	credentials := NewQiniuCredentials(testAccessKey, testSecretKey)

	early, err := credentials.SignDownloadURL("http://model.example.com", "a.zip", time.Unix(testDeadline, 0))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	late, err := credentials.SignDownloadURL("http://model.example.com", "a.zip", time.Unix(testDeadline+1, 0))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if early == late {
		t.Fatal("不同过期时间签出了同一个地址")
	}
}

func TestSignDownloadURLRejectsIncompleteConfig(t *testing.T) {
	expiresAt := time.Unix(testDeadline, 0)

	if _, err := NewQiniuCredentials("", testSecretKey).
		SignDownloadURL("http://model.example.com", "a.zip", expiresAt); !errors.Is(err, ErrQiniuCredentialsMissing) {
		t.Fatalf("缺 accessKey 时应返回 ErrQiniuCredentialsMissing，实际: %v", err)
	}
	if _, err := NewQiniuCredentials(testAccessKey, "").
		SignDownloadURL("http://model.example.com", "a.zip", expiresAt); !errors.Is(err, ErrQiniuCredentialsMissing) {
		t.Fatalf("缺 secretKey 时应返回 ErrQiniuCredentialsMissing，实际: %v", err)
	}
	if _, err := NewQiniuCredentials(testAccessKey, testSecretKey).
		SignDownloadURL("", "a.zip", expiresAt); !errors.Is(err, ErrQiniuDomainMissing) {
		t.Fatalf("缺 domain 时应返回 ErrQiniuDomainMissing，实际: %v", err)
	}
}
