// Package authtoken 提供与具体业务无关的登录态 token 签发与校验能力。
// 只处理 token 与用户 uid 之间的映射关系，不感知手机号、微信 openid 等具体登录方式，
// 业务项目拿到 uid 后自行关联自己的用户信息。
package authtoken

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/zehongyang/bee/rds"
)

// ErrInvalidToken 表示 token 不存在、已过期或格式非法。
var ErrInvalidToken = errors.New("invalid token")

// keyPrefix 是 token 在 Redis 里的 key 前缀，避免和其他业务 key 冲突。
const keyPrefix = "bee:authtoken:"

// Issue 为指定 uid 签发一个新的登录态 token，写入 Redis 并设置过期时间 ttl，返回生成的 token 字符串。
func Issue(rdsName string, uid int64, ttl time.Duration) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	client := rds.Get(rdsName)
	err = client.Set(context.Background(), keyPrefix+token, uid, ttl).Err()
	if err != nil {
		return "", err
	}
	return token, nil
}

// Verify 校验 token 是否有效，有效时返回其绑定的 uid；不存在或已过期时返回 ErrInvalidToken。
func Verify(rdsName string, token string) (int64, error) {
	if token == "" {
		return 0, ErrInvalidToken
	}
	client := rds.Get(rdsName)
	val, err := client.Get(context.Background(), keyPrefix+token).Result()
	if err != nil {
		return 0, ErrInvalidToken
	}
	uid, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, ErrInvalidToken
	}
	return uid, nil
}

// Revoke 让指定 token 立即失效，用于登出场景；token 本身不存在时视为成功。
func Revoke(rdsName string, token string) error {
	if token == "" {
		return nil
	}
	client := rds.Get(rdsName)
	return client.Del(context.Background(), keyPrefix+token).Err()
}

// randomToken 生成一个 32 字节随机数的十六进制字符串，作为不可猜测的登录态 token。
func randomToken() (string, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
