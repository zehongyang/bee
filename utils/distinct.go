package utils

func Distinct[T comparable](arr []T) []T {
	var mp = make(map[T]struct{})
	for _, t := range arr {
		mp[t] = struct{}{}
	}
	var result = make([]T, 0, len(mp))
	for t, _ := range mp {
		result = append(result, t)
	}
	return result
}

func DistinctStruct[T any, K comparable](arr []T, fn func(T) K) []T {
	var mp = make(map[K]T)
	for _, t := range arr {
		mp[fn(t)] = t
	}
	var result = make([]T, 0, len(mp))
	for _, t := range mp {
		result = append(result, t)
	}
	return result
}
