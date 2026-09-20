package safenet

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

func TestIsRestrictedIP(t *testing.T) {
	testCases := []struct {
		ip       string
		blocked  bool
		category string
	}{
		{"127.0.0.1", true, "loopback"},
		{"127.1.2.3", true, "loopback range"},
		{"::1", true, "ipv6 loopback"},
		{"::ffff:127.0.0.1", true, "ipv4-mapped ipv6 loopback"},
		{"10.0.0.1", true, "rfc1918 10/8"},
		{"10.254.254.254", true, "rfc1918 10/8"},
		{"172.16.0.1", true, "rfc1918 172.16/12"},
		{"172.31.255.255", true, "rfc1918 172.16/12"},
		{"192.168.1.1", true, "rfc1918 192.168/16"},
		{"169.254.169.254", true, "cloud metadata"},
		{"169.254.1.1", true, "link-local"},
		{"0.0.0.0", true, "unspecified"},
		{"255.255.255.255", true, "broadcast"},
		{"100.64.0.1", true, "carrier-grade nat"},
		{"192.0.2.1", true, "documentation range"},
		{"fc00::1", true, "ipv6 unique local"},
		{"fe80::1", true, "ipv6 link-local"},
		{"8.8.8.8", false, "public google dns"},
		{"1.1.1.1", false, "public cloudflare dns"},
		{"93.184.216.34", false, "public example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.ip+"_"+tc.category, func(t *testing.T) {
			parsed := net.ParseIP(tc.ip)
			if parsed == nil {
				t.Fatalf("failed to parse IP %s", tc.ip)
			}
			restricted, reason := IsRestrictedIP(parsed)
			if restricted != tc.blocked {
				t.Errorf("expected blocked=%v for %s (%s), got restricted=%v, reason=%s", tc.blocked, tc.ip, tc.category, restricted, reason)
			}
		})
	}
}

func TestSafeDialer_BlocksDirectPrivateIP(t *testing.T) {
	dialCtx := NewSafeDialContext(1 * time.Second)

	// Attempt to dial 127.0.0.1
	_, err := dialCtx(context.Background(), "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected dial to 127.0.0.1 to be blocked by safe dialer, but got nil error")
	}
	if !containsError(err, ErrRestrictedIP) {
		t.Errorf("expected error to wrap ErrRestrictedIP, got: %v", err)
	}

	// Attempt to dial 169.254.169.254
	_, err = dialCtx(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("expected dial to 169.254.169.254 to be blocked, but got nil error")
	}
}

func TestSafeHTTPClient_BlocksRedirectToInternal(t *testing.T) {
	// Setup target with scope for example.com
	target := &models.Target{
		ID:             "tgt-test",
		Name:           "example.com",
		AllowedDomains: []string{"example.com"},
	}
	scopeValidator := scope.NewValidator()

	client := NewSafeHTTPClient(2*time.Second, 3, scopeValidator, target)

	initialReq, _ := http.NewRequest("GET", "https://example.com/login", nil)
	metadataReq, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil)

	err := client.CheckRedirect(metadataReq, []*http.Request{initialReq})
	if err == nil {
		t.Fatal("expected redirect to 169.254.169.254 to be blocked, got nil error")
	}
	if !containsError(err, ErrSSRFRedirectBlocked) {
		t.Errorf("expected ErrSSRFRedirectBlocked, got: %v", err)
	}
}

func TestSafeHTTPClient_BlocksRedirectOutOfScope(t *testing.T) {
	target := &models.Target{
		ID:             "tgt-test",
		Name:           "auth.example.com",
		AllowedDomains: []string{"auth.example.com"},
	}
	scopeValidator := scope.NewValidator()

	client := NewSafeHTTPClient(2*time.Second, 3, scopeValidator, target)

	// Direct CheckRedirect validation
	initialReq, _ := http.NewRequest("GET", "https://auth.example.com/login", nil)
	redirectReq, _ := http.NewRequest("GET", "https://evil-unauthorized-target.org/leak", nil)

	err := client.CheckRedirect(redirectReq, []*http.Request{initialReq})
	if err == nil {
		t.Fatal("expected redirect to unauthorized domain to be blocked by scope boundary, got nil error")
	}
	if !containsError(err, ErrRedirectOutOfScope) {
		t.Errorf("expected ErrRedirectOutOfScope, got: %v", err)
	}

	// Verify redirect to internal metadata is blocked
	metadataReq, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil)
	err = client.CheckRedirect(metadataReq, []*http.Request{initialReq})
	if err == nil {
		t.Fatal("expected redirect to internal metadata to be blocked, got nil error")
	}
	if !containsError(err, ErrSSRFRedirectBlocked) {
		t.Errorf("expected ErrSSRFRedirectBlocked, got: %v", err)
	}
}

func containsError(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	return err == target || (len(err.Error()) > 0 && len(target.Error()) > 0 && 
		(err.Error() == target.Error() || netErrorContains(err.Error(), target.Error())))
}

func netErrorContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
