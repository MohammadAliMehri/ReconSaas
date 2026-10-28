package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

var (
	ErrResponseTooLarge = errors.New("response exceeded maximum allowed byte limit")
	ErrRedirectBlocked  = errors.New("redirect target was rejected by scope policy")
)

// Response wraps HTTP response attributes for consistent module consumption.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Cookies    []*http.Cookie
	URL        string
}

// Client defines the scoped networking interface required by modules.
type Client interface {
	Get(ctx context.Context, targetURL string, headers map[string]string) (*Response, error)
	Post(ctx context.Context, targetURL string, headers map[string]string, body []byte) (*Response, error)
	Do(req *http.Request) (*Response, error)
	DialTCP(ctx context.Context, address string) (net.Conn, error)
}

// Config defines options for creating a ScopedClient.
type Config struct {
	Timeout          time.Duration
	RateLimitDelay   time.Duration
	MaxResponseBytes int64
	MaxRedirects     int
	UserAgent        string
	FollowRedirects  bool
	InsecureSkipTLS  bool
}

// ScopedClient implements Client with strict scope validation, rate limits, and size caps.
type ScopedClient struct {
	scopeEngine *scope.Engine
	config      Config
	httpClient  *http.Client
	mu          sync.Mutex
	lastReqTime time.Time
}

// NewScopedClient instantiates a safe, scope-enforcing HTTP and TCP client.
func NewScopedClient(scopeEngine *scope.Engine, cfg Config) *ScopedClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 2 * 1024 * 1024 // 2 MB default cap
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "ReconSaas/3.0 (Security Research)"
	}

	sc := &ScopedClient{
		scopeEngine: scopeEngine,
		config:      cfg,
	}

	// Custom transport with safe dialer validating IP addresses
	dialer := &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Validate IP addresses resolved before dialing
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			var dialErr error
			for _, ip := range ips {
				if err := scopeEngine.IsIPAllowed(ip); err != nil {
					dialErr = err
					continue
				}
				// Dial the validated IP directly
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}

			if dialErr != nil {
				return nil, dialErr
			}
			return nil, fmt.Errorf("no allowed IP address found for host %s", host)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS, // #nosec G402
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	sc.httpClient = &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= cfg.MaxRedirects && cfg.MaxRedirects > 0 {
				return fmt.Errorf("stopped after %d redirects", cfg.MaxRedirects)
			}
			// Re-verify redirect URL against scope
			if err := scopeEngine.ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("%w: %v", ErrRedirectBlocked, err)
			}
			return nil
		},
	}

	return sc
}

// waitRateLimit enforces rate limit pause between requests.
func (c *ScopedClient) waitRateLimit(ctx context.Context) error {
	if c.config.RateLimitDelay <= 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.lastReqTime)
	if elapsed < c.config.RateLimitDelay {
		wait := c.config.RateLimitDelay - elapsed
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	c.lastReqTime = time.Now()
	return nil
}

// Do executes an HTTP request subject to scope checks, rate limits, and size caps.
func (c *ScopedClient) Do(req *http.Request) (*Response, error) {
	if err := c.scopeEngine.ValidateURL(req.URL.String()); err != nil {
		return nil, err
	}

	if err := c.waitRateLimit(req.Context()); err != nil {
		return nil, err
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Enforce response body read cap
	limitedReader := io.LimitReader(resp.Body, c.config.MaxResponseBytes+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if int64(len(bodyBytes)) > c.config.MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       bodyBytes,
		Cookies:    resp.Cookies(),
		URL:        resp.Request.URL.String(),
	}, nil
}

// Get performs a scoped GET request.
func (c *ScopedClient) Get(ctx context.Context, targetURL string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

// Post performs a scoped POST request.
func (c *ScopedClient) Post(ctx context.Context, targetURL string, headers map[string]string, body []byte) (*Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

// DialTCP establishes a scoped TCP connection after verifying IP authorization.
func (c *ScopedClient) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: c.config.Timeout}
	for _, ip := range ips {
		if err := c.scopeEngine.IsIPAllowed(ip); err == nil {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		}
	}

	return nil, fmt.Errorf("no allowed IP found for address %s", address)
}

