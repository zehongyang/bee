package utils

import "golang.org/x/exp/constraints"

func Abs[T constraints.Integer](num T) T {
	if num < 0 {
		return -num
	}
	return num
}
