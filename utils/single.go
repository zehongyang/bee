package utils

import (
	"sync"
)

func Single[T any](fn func() T) func() T {
	var (
		once sync.Once
		t    T
	)
	return func() T {
		once.Do(func() {
			t = fn()
		})
		return t
	}
}
