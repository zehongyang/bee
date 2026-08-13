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

// Store 是一个带命名空间的登录态存储。
//
// 存在的理由是**隔离两套互不相干的登录态**。同一个项目里往往不止一种身份：
// App 用户是一套，管理后台又是一套。它们的 uid 都是 int64，如果共用同一个 key 空间，
// Verify 只能告诉你"这个 token 对应 uid 5"，分辨不出这个 5 是普通用户还是管理员——
// 于是任意一个普通用户的 token 都能通过管理后台的鉴权。
//
// 用不同的 namespace 建两个 Store，两边的 token 在 Redis 里落在不同的 key 上，
// 一边签发的 token 在另一边根本查不到，越权就成了不可能而不是"记得检查"。
type Store struct {
	rdsName   string
	namespace string
}

// New 创建一个带命名空间的登录态存储。namespace 为空时等价于包级函数的默认空间。
func New(rdsName, namespace string) *Store {
	return &Store{rdsName: rdsName, namespace: namespace}
}

// key 返回 token 在 Redis 里的完整键名。
func (s *Store) key(token string) string {
	if s.namespace == "" {
		return keyPrefix + token
	}
	return keyPrefix + s.namespace + ":" + token
}

// Issue 为指定 uid 在本命名空间下签发一个新的登录态 token。
func (s *Store) Issue(uid int64, ttl time.Duration) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	client := rds.Get(s.rdsName)
	if err = client.Set(context.Background(), s.key(token), uid, ttl).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// Verify 校验 token 在本命名空间下是否有效，有效时返回其绑定的 uid。
// 别的命名空间签发的 token 在这里一律返回 ErrInvalidToken——这正是隔离的意义所在。
func (s *Store) Verify(token string) (int64, error) {
	if token == "" {
		return 0, ErrInvalidToken
	}
	client := rds.Get(s.rdsName)
	val, err := client.Get(context.Background(), s.key(token)).Result()
	if err != nil {
		return 0, ErrInvalidToken
	}
	uid, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, ErrInvalidToken
	}
	return uid, nil
}

// Revoke 让本命名空间下的指定 token 立即失效；token 不存在时视为成功。
func (s *Store) Revoke(token string) error {
	if token == "" {
		return nil
	}
	client := rds.Get(s.rdsName)
	return client.Del(context.Background(), s.key(token)).Err()
}

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
