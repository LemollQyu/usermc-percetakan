package utils

import (
	"math/rand"
	"time"
)

func GenerateOTP(length int) string {
	digits := "0123456789"
	otp := make([]byte, length)
	rand.Seed(time.Now().UnixNano())

	for i := range otp {
		otp[i] = digits[rand.Intn(len(digits))]
	}

	return string(otp)
}

func ExpireOTP3Minutes() time.Time {
	return time.Now().Add(3 * time.Minute)
}

func SecondsUntil(exp time.Time) int {
	diff := exp.Sub(time.Now()).Seconds()
	if diff < 0 {
		return 0
	}
	return int(diff)
}
