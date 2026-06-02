package ws

import (
	"net"
	"net/http"
	"strings"
)

var (
	trustedProxies = map[string]struct{}{
		"127.0.0.1": {},
		"::1":       {},
	}
)

func getClientIP(r *http.Request) string {

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// если НЕ доверенный прокси — всегда RemoteAddr
	if _, ok := trustedProxies[host]; !ok {
		return host
	}

	// X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(strings.Split(xff, ",")[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// X-Real-IP
	if rip := r.Header.Get("X-Real-IP"); net.ParseIP(rip) != nil {
		return rip
	}

	return host
}
