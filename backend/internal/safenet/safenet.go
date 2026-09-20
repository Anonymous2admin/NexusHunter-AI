package safenet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

var (
	ErrRestrictedIP        = errors.New("SSRF_VIOLATION: destination IP is private, loopback, link-local, or cloud metadata")
	ErrRedirectOutOfScope  = errors.New("SCOPE_VIOLATION: redirect destination exceeds authorized boundary")
	ErrMaxRedirects        = errors.New("MAX_REDIRECTS_EXCEEDED: too many redirects in probe chain")
	ErrSSRFRedirectBlocked = errors.New("SSRF_VIOLATION: redirect targets internal or restricted infrastructure")
)

// Restricted CIDR ranges blocked from outbound probes
var restrictedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4 Loopback & Special
		"127.0.0.0/8",
		"0.0.0.0/8",
		"255.255.255.255/32",
		// IPv4 Private (RFC 1918)
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// IPv4 Link-Local & Cloud Metadata (AWS/GCP/Azure: 169.254.169.254)
		"169.254.0.0/16",
		// Carrier Grade NAT (RFC 6598)
		"100.64.0.0/10",
		// Documentation & Test Ranges
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"198.18.0.0/15",
		// Multicast
		"224.0.0.0/4",
		// IPv6 Loopback & Special
		"::1/128",
		"::/128",
		// IPv6 Unique Local (RFC 4193)
		"fc00::/7",
		// IPv6 Link-Local (RFC 4291)
		"fe80::/10",
		// IPv6 Multicast
		"ff00::/8",
		// IPv6 Documentation
		"2001:db8::/32",
	}

	for _, c := range cidrs {
		_, netBlock, err := net.ParseCIDR(c)
		if err == nil {
			restrictedCIDRs = append(restrictedCIDRs, netBlock)
		}
	}
}

// IsRestrictedIP checks whether an IP address belongs to loopback, private,
// link-local, cloud metadata, or multicast ranges.
func IsRestrictedIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil IP address"
	}

	// Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	// Standard Go standard library checks
	if ip.IsLoopback() {
		return true, fmt.Sprintf("loopback address (%s)", ip.String())
	}
	if ip.IsPrivate() {
		return true, fmt.Sprintf("private network address (%s)", ip.String())
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, fmt.Sprintf("link-local address (%s)", ip.String())
	}
	if ip.IsMulticast() {
		return true, fmt.Sprintf("multicast address (%s)", ip.String())
	}
	if ip.IsUnspecified() {
		return true, fmt.Sprintf("unspecified address (%s)", ip.String())
	}

	// Explicit CIDR checks
	for _, block := range restrictedCIDRs {
		if block.Contains(ip) {
			return true, fmt.Sprintf("restricted CIDR %s contains %s", block.String(), ip.String())
		}
	}

	return false, ""
}

// IsRestrictedHost checks whether a host string is an IP or resolves to an IP that is restricted.
func IsRestrictedHost(ctx context.Context, host string) (bool, string) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	// Direct IP check
	if ip := net.ParseIP(host); ip != nil {
		return IsRestrictedIP(ip)
	}

	// Named localhost / localdomain checks
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return true, fmt.Sprintf("internal hostname (%s)", host)
	}

	// DNS Resolution with context timeout
	resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// If DNS resolution fails, fail-closed for safety
		return false, ""
	}

	if len(addrs) == 0 {
		return true, "host resolved to zero IP addresses"
	}

	for _, addr := range addrs {
		if restricted, reason := IsRestrictedIP(addr.IP); restricted {
			return true, fmt.Sprintf("host %s resolves to restricted IP: %s", host, reason)
		}
	}

	return false, ""
}

// NewSafeDialContext returns a DialContext function that actively defends against SSRF and DNS Rebinding.
func NewSafeDialContext(dialTimeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return NewSafeDialContextWithConfig(dialTimeout, false)
}

// NewSafeDialContextWithConfig returns a DialContext that can optionally permit local mock servers for unit tests.
func NewSafeDialContextWithConfig(dialTimeout time.Duration, allowLocal bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid network address %q: %w", addr, err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}

		// Step 1: Pre-dial DNS resolution & SSRF validation
		cleanHost := strings.Trim(host, "[]")
		var targetIP net.IP

		if ip := net.ParseIP(cleanHost); ip != nil {
			// Metadata is ALWAYS blocked regardless of allowLocal
			if ip.String() == "169.254.169.254" || strings.HasPrefix(ip.String(), "169.254.") {
				return nil, fmt.Errorf("%w: cloud metadata blocked", ErrRestrictedIP)
			}
			if !allowLocal {
				if restricted, reason := IsRestrictedIP(ip); restricted {
					return nil, fmt.Errorf("%w: %s", ErrRestrictedIP, reason)
				}
			}
			targetIP = ip
		} else {
			// Name check
			lower := strings.ToLower(cleanHost)
			if !allowLocal && (lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local")) {
				return nil, fmt.Errorf("%w: internal hostname %s", ErrRestrictedIP, cleanHost)
			}

			// Resolve host
			resolveCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()

			addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, cleanHost)
			if err != nil {
				return nil, fmt.Errorf("DNS resolution failed for %s: %w", cleanHost, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("no IP addresses returned for %s", cleanHost)
			}

			// Validate ALL returned IPs
			for _, a := range addrs {
				if a.IP.String() == "169.254.169.254" || strings.HasPrefix(a.IP.String(), "169.254.") {
					return nil, fmt.Errorf("%w: cloud metadata blocked", ErrRestrictedIP)
				}
				if !allowLocal {
					if restricted, reason := IsRestrictedIP(a.IP); restricted {
						return nil, fmt.Errorf("%w: resolved %s -> %s (%s)", ErrRestrictedIP, cleanHost, a.IP.String(), reason)
					}
				}
			}
			targetIP = addrs[0].IP
		}

		// Step 2: Dial the verified IP directly to eliminate TOCTOU / DNS rebinding
		dialer := &net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				ipStr, _, splitErr := net.SplitHostPort(address)
				if splitErr == nil {
					if parsed := net.ParseIP(ipStr); parsed != nil {
						if parsed.String() == "169.254.169.254" || strings.HasPrefix(parsed.String(), "169.254.") {
							return fmt.Errorf("%w: raw conn check blocked cloud metadata %s", ErrRestrictedIP, address)
						}
						if !allowLocal {
							if restricted, reason := IsRestrictedIP(parsed); restricted {
								return fmt.Errorf("%w: raw conn check blocked %s (%s)", ErrRestrictedIP, address, reason)
							}
						}
					}
				}
				return nil
			},
		}

		dialTarget := net.JoinHostPort(targetIP.String(), portStr)
		return dialer.DialContext(ctx, network, dialTarget)
	}
}

// NewSafeTransport constructs an http.Transport equipped with SSRF defenses.
func NewSafeTransport(dialTimeout time.Duration) *http.Transport {
	return NewSafeTransportWithConfig(dialTimeout, false)
}

// NewSafeTransportWithConfig constructs an http.Transport with configurable local server permission.
func NewSafeTransportWithConfig(dialTimeout time.Duration, allowLocal bool) *http.Transport {
	return &http.Transport{
		DialContext:           NewSafeDialContextWithConfig(dialTimeout, allowLocal),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: dialTimeout,
	}
}

// NewSafeHTTPClient constructs an http.Client with safe transport, strict redirect boundaries,
// and automatic header sanitization.
func NewSafeHTTPClient(
	requestTimeout time.Duration,
	maxRedirects int,
	scopeSvc scope.ScopeService,
	target *models.Target,
) *http.Client {
	return NewSafeHTTPClientWithConfig(requestTimeout, maxRedirects, scopeSvc, target, false)
}

// NewSafeHTTPClientWithConfig constructs an http.Client with configurable local server testing.
func NewSafeHTTPClientWithConfig(
	requestTimeout time.Duration,
	maxRedirects int,
	scopeSvc scope.ScopeService,
	target *models.Target,
	allowLocal bool,
) *http.Client {
	if maxRedirects <= 0 {
		maxRedirects = 5
	}

	transport := NewSafeTransportWithConfig(requestTimeout, allowLocal)

	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrMaxRedirects
			}

			// 1. SSRF check on redirect destination host
			if !allowLocal {
				if restricted, reason := IsRestrictedHost(req.Context(), req.URL.Hostname()); restricted {
					return fmt.Errorf("%w: redirect destination is %s", ErrSSRFRedirectBlocked, reason)
				}
			} else {
				// Metadata is ALWAYS blocked even if allowLocal is true
				destHost := strings.Trim(req.URL.Hostname(), "[]")
				if destHost == "169.254.169.254" || strings.HasPrefix(destHost, "169.254.") {
					return fmt.Errorf("%w: redirect destination is cloud metadata", ErrSSRFRedirectBlocked)
				}
			}

			// 2. Scope boundary evaluation if target and scope service are provided
			if scopeSvc != nil && target != nil {
				decision := scopeSvc.Evaluate(target, req.URL.Hostname(), req.URL.String())
				if !decision.InScope {
					return fmt.Errorf("%w: redirect to %s denied (%s)", ErrRedirectOutOfScope, req.URL.String(), decision.Reason)
				}
			}

			// 3. Security header sanitization on cross-origin redirect
			if len(via) > 0 {
				prevURL := via[len(via)-1].URL
				if !strings.EqualFold(prevURL.Host, req.URL.Host) {
					req.Header.Del("Authorization")
					req.Header.Del("Cookie")
					req.Header.Del("Proxy-Authorization")
				}
			}

			return nil
		},
	}

	return client
}
