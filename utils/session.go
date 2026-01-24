package utils

import (
	"encoding/hex"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

func GenerateExpiry(hours int) time.Time {
	return time.Now().Add(time.Duration(hours) * time.Hour)
}

func GenerateExpiryUnix(hours int) int64 {
	return time.Now().Add(time.Duration(hours) * time.Hour).Unix()
}

func GenerateRandomToken() (string, error) {
	token := make([]byte, 32)

	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(token), nil
}

func GetClientIP(r *http.Request) string {

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	xrip := r.Header.Get("X-Real-IP")
	if xrip != "" {
		return xrip
	}

	cfip := r.Header.Get("CF-Connecting-IP")
	if cfip != "" {
		return cfip
	}

	// 4. Fallback RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func GetUserAgent(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return "unknown"
	}
	return ua
}
