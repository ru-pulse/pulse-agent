// Package guardrails contains the limits that make this agent safe to install.
//
// Everything here is enforced locally, in open-source code, and none of it can
// be raised by the control plane: not by a task field, not by a config push,
// not by a server response. A fully compromised control plane can still only
// make this agent fetch a status code from a public web server, slowly.
package guardrails

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// MaxChecksPerMinute is a hard ceiling per agent process.
	MaxChecksPerMinute = 30
	// PerTargetCooldown stops the same host being checked in a tight loop,
	// no matter how many tasks name it.
	PerTargetCooldown = 20 * time.Second
	// MaxTaskAge rejects stale tasks replayed from a queue backlog.
	MaxTaskAge = 5 * time.Minute
)

var (
	allowedMethods = map[string]bool{"GET": true, "HEAD": true}
	allowedPorts   = map[int]bool{80: true, 443: true}
	allowedSchemes = map[string]bool{"http": true, "https": true}
)

// privateOrReserved lists everything an agent must refuse to connect to. The
// point is that a check target is always somewhere on the public internet:
// this agent can never be pointed at a partner's LAN, their router, or a cloud
// metadata endpoint.
var privateOrReserved = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4",
	"::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
}

var reservedNets []*net.IPNet

func init() {
	for _, cidr := range privateOrReserved {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("guardrails: bad built-in CIDR " + cidr)
		}
		reservedNets = append(reservedNets, network)
	}
}

func IsPrivateOrReserved(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, network := range reservedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// RateLimiter is a sliding window over the last minute.
type RateLimiter struct {
	mu     sync.Mutex
	max    int
	stamps []time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{max: MaxChecksPerMinute}
}

// SetLimit опускает лимит ниже зашитого потолка по желанию пользователя.
//
// Зажатие делается здесь, а не в вызывающем коде, намеренно: верхняя граница
// должна оставаться недостижимой из любой точки программы, иначе однажды
// появится путь её обойти. Значение выше потолка молча становится потолком.
func (r *RateLimiter) SetLimit(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n < 1 {
		n = 1
	}
	if n > MaxChecksPerMinute {
		n = MaxChecksPerMinute
	}
	r.max = n
}

func (r *RateLimiter) Limit() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	kept := r.stamps[:0]
	for _, ts := range r.stamps {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	r.stamps = kept
	if len(r.stamps) >= r.max {
		return false
	}
	r.stamps = append(r.stamps, time.Now())
	return true
}

// Cooldown enforces a minimum gap between checks of the same host.
type Cooldown struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func NewCooldown() *Cooldown {
	return &Cooldown{last: make(map[string]time.Time)}
}

func (c *Cooldown) Allow(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if seen, ok := c.last[domain]; ok && now.Sub(seen) < PerTargetCooldown {
		return false
	}
	c.last[domain] = now
	if len(c.last) > 10000 {
		for key, ts := range c.last {
			if now.Sub(ts) > PerTargetCooldown*10 {
				delete(c.last, key)
			}
		}
	}
	return true
}

type TaskSpec struct {
	Domain   string
	Port     int
	Scheme   string
	Path     string
	Method   string
	IssuedAt time.Time
}

// ValidateTask is the schema the control plane is allowed to ask for. Anything
// outside it is dropped before a single packet is sent.
func ValidateTask(spec TaskSpec) error {
	if !allowedMethods[spec.Method] {
		return fmt.Errorf("method %q not allowed (only GET/HEAD)", spec.Method)
	}
	if !allowedPorts[spec.Port] {
		return fmt.Errorf("port %d not allowed (only 80/443)", spec.Port)
	}
	if !allowedSchemes[spec.Scheme] {
		return fmt.Errorf("scheme %q not allowed", spec.Scheme)
	}
	if spec.Domain == "" || len(spec.Domain) > 253 || strings.ContainsAny(spec.Domain, " /\\@") {
		return fmt.Errorf("invalid domain %q", spec.Domain)
	}
	if net.ParseIP(spec.Domain) != nil {
		// Only names, never bare addresses: keeps the agent from being aimed
		// at arbitrary hosts and keeps results comparable across agents.
		return fmt.Errorf("target must be a domain name, not an IP literal")
	}
	if !strings.HasPrefix(spec.Path, "/") || len(spec.Path) > 2048 {
		return fmt.Errorf("invalid path")
	}
	if !spec.IssuedAt.IsZero() && time.Since(spec.IssuedAt) > MaxTaskAge {
		return fmt.Errorf("task is stale (issued %s ago)", time.Since(spec.IssuedAt).Round(time.Second))
	}
	return nil
}

// ResolvePublicAddr resolves a domain and refuses the whole check if ANY
// returned address is private — the DNS-rebinding-safe version of "is this
// target public?".
func ResolvePublicAddr(ctx context.Context, domain string) (net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no DNS records for %s", domain)
	}
	for _, addr := range addrs {
		if IsPrivateOrReserved(addr.IP) {
			return nil, fmt.Errorf("refusing private/reserved target address %s", addr.IP)
		}
	}
	return addrs[0].IP, nil
}
