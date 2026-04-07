package caches

import (
	"github.com/hashicorp/golang-lru/v2/expirable"
	"time"
)

type Cache[K comparable, V any] struct {
	*expirable.LRU[K, V]
}

func NewCache[K comparable, V any](size int, duration time.Duration) *Cache[K, V] {
	return &Cache[K, V]{expirable.NewLRU[K, V](size, nil, duration)}
}
