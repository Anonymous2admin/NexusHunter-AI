package recon

import (
	"context"
	"net"
	"strings"
	"time"
)

// DNSResolver defines the interface for resolving hostnames into DNS records.
type DNSResolver interface {
	Resolve(ctx context.Context, hostname string) ([]DNSResult, error)
}

// StandardDNSResolver performs concurrent A, AAAA, and CNAME lookups using net.Resolver.
type StandardDNSResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewStandardDNSResolver returns an initialized DNS resolver with specified per-query timeout.
func NewStandardDNSResolver(timeout time.Duration) *StandardDNSResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &StandardDNSResolver{
		resolver: &net.Resolver{
			PreferGo: true,
		},
		timeout: timeout,
	}
}

// Resolve resolves A, AAAA, and CNAME records for a normalized hostname.
func (r *StandardDNSResolver) Resolve(ctx context.Context, hostname string) ([]DNSResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	results := make([]DNSResult, 0)
	now := time.Now().UTC()

	// 1. Resolve IP addresses (A and AAAA)
	ips, err := r.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		status := "ERROR"
		var netErr net.Error
		if ok := errorAsNetError(err, &netErr); ok && netErr.Timeout() {
			status = "TIMEOUT"
		} else if strings.Contains(strings.ToLower(err.Error()), "no such host") {
			status = "NXDOMAIN"
		}

		results = append(results, DNSResult{
			Hostname:   hostname,
			RecordType: "A",
			Value:      "",
			Status:     status,
			Timestamp:  now,
		})
		return results, nil
	}

	for _, ip := range ips {
		recordType := "A"
		if ip.IP.To4() == nil {
			recordType = "AAAA"
		}
		results = append(results, DNSResult{
			Hostname:   hostname,
			RecordType: recordType,
			Value:      ip.IP.String(),
			Status:     "NOERROR",
			Timestamp:  now,
		})
	}

	// 2. Resolve CNAME (if exists)
	cname, err := r.resolver.LookupCNAME(ctx, hostname)
	if err == nil {
		cleanCNAME := strings.TrimSuffix(strings.TrimSpace(cname), ".")
		if cleanCNAME != "" && cleanCNAME != hostname {
			results = append(results, DNSResult{
				Hostname:   hostname,
				RecordType: "CNAME",
				Value:      cleanCNAME,
				Status:     "NOERROR",
				Timestamp:  now,
			})
		}
	}

	return results, nil
}

func errorAsNetError(err error, target *net.Error) bool {
	if nErr, ok := err.(net.Error); ok {
		*target = nErr
		return true
	}
	return false
}
