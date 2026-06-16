package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

// httpPorts are scanned over plain HTTP; httpsPorts over TLS.
var httpPorts = map[int]bool{80: true, 8080: true, 8000: true, 8081: true, 3000: true, 9000: true, 8888: true}
var httpsPorts = map[int]bool{443: true, 8443: true}

// IsHTTPPort reports whether a port should get an HTTP audit.
func IsHTTPPort(port int) bool { return httpPorts[port] || httpsPorts[port] }

// securityHeaders are the headers we grade a response against.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// AuditHTTP fetches the root path and grades security headers.
func AuditHTTP(ctx context.Context, ip string, port int, timeout time.Duration) (model.HTTPInfo, bool) {
	info := model.HTTPInfo{Port: port, PresentHeaders: map[string]string{}}

	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, false
	}
	req.Header.Set("User-Agent", "dragnet/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return info, false
	}
	defer resp.Body.Close()

	info.StatusCode = resp.StatusCode
	info.Server = resp.Header.Get("Server")

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if m := titleRe.FindSubmatch(body); len(m) == 2 {
		info.Title = strings.TrimSpace(string(m[1]))
		if len(info.Title) > 80 {
			info.Title = info.Title[:80] + "..."
		}
	}

	for _, h := range securityHeaders {
		if v := resp.Header.Get(h); v != "" {
			info.PresentHeaders[h] = v
		} else {
			info.MissingHeaders = append(info.MissingHeaders, h)
		}
	}
	info.SecurityScore = 100 * len(info.PresentHeaders) / len(securityHeaders)

	return info, true
}
