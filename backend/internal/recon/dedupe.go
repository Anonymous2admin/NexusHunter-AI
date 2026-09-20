package recon

import (
	"sync"
)

// Deduplicator manages thread-safe in-memory deduplication sets for a reconnaissance run.
type Deduplicator struct {
	mu           sync.RWMutex
	hostnames    map[string]struct{}
	ips          map[string]struct{}
	urls         map[string]struct{}
	dnsRecords   map[string]struct{} // key: hostname + ":" + recordType + ":" + value
	httpServices map[string]struct{} // key: method + ":" + url
}

// NewDeduplicator initializes a clean deduplication instance.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		hostnames:    make(map[string]struct{}),
		ips:          make(map[string]struct{}),
		urls:         make(map[string]struct{}),
		dnsRecords:   make(map[string]struct{}),
		httpServices: make(map[string]struct{}),
	}
}

// CheckAndAddHost returns true if the host is new and marks it as seen.
// Returns false if the host was already observed.
func (d *Deduplicator) CheckAndAddHost(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.hostnames[host]; exists {
		return false
	}
	d.hostnames[host] = struct{}{}
	return true
}

// CheckAndAddIP returns true if the IP is new and marks it as seen.
func (d *Deduplicator) CheckAndAddIP(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.ips[ip]; exists {
		return false
	}
	d.ips[ip] = struct{}{}
	return true
}

// CheckAndAddURL returns true if the normalized URL is new and marks it as seen.
func (d *Deduplicator) CheckAndAddURL(canonicalURL string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.urls[canonicalURL]; exists {
		return false
	}
	d.urls[canonicalURL] = struct{}{}
	return true
}

// CheckAndAddDNS returns true if the DNS record (host:type:value) is new and marks it as seen.
func (d *Deduplicator) CheckAndAddDNS(host, recordType, value string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := host + ":" + recordType + ":" + value
	if _, exists := d.dnsRecords[key]; exists {
		return false
	}
	d.dnsRecords[key] = struct{}{}
	return true
}

// CheckAndAddHTTPService returns true if the HTTP service observation is new and marks it as seen.
func (d *Deduplicator) CheckAndAddHTTPService(url string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.httpServices[url]; exists {
		return false
	}
	d.httpServices[url] = struct{}{}
	return true
}

// Count returns the counts of deduplicated entities.
func (d *Deduplicator) Count() (hosts, urls, dns, svcs int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.hostnames), len(d.urls), len(d.dnsRecords), len(d.httpServices)
}
