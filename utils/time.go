package utils

import "time"

const (
	Time1SMs    = 1000
	Time1MinMs  = 60 * Time1SMs
	Time1HourMs = 60 * Time1MinMs
	Time1DayMs  = 24 * Time1HourMs
)

func Now() int64 {
	return time.Now().UnixMilli()
}
