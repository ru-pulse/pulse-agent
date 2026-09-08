package guardrails

import (
	"net"
	"testing"
	"time"
)

func validSpec() TaskSpec {
	return TaskSpec{
		Domain: "example.com", Port: 443, Scheme: "https",
		Path: "/", Method: "GET", IssuedAt: time.Now(),
	}
}

func TestValidateTaskAcceptsAWellFormedTask(t *testing.T) {
	if err := ValidateTask(validSpec()); err != nil {
		t.Fatalf("valid task rejected: %v", err)
	}
}

// Each case is something a compromised control plane might try to talk this
// agent into doing. All of them must be refused locally.
func TestValidateTaskRefusesAbuse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*TaskSpec)
	}{
		{"POST request", func(s *TaskSpec) { s.Method = "POST" }},
		{"DELETE request", func(s *TaskSpec) { s.Method = "DELETE" }},
		{"SSH port", func(s *TaskSpec) { s.Port = 22 }},
		{"database port", func(s *TaskSpec) { s.Port = 5432 }},
		{"high port scan", func(s *TaskSpec) { s.Port = 31337 }},
		{"non-http scheme", func(s *TaskSpec) { s.Scheme = "ftp" }},
		{"IPv4 literal target", func(s *TaskSpec) { s.Domain = "192.168.1.1" }},
		{"public IPv4 literal target", func(s *TaskSpec) { s.Domain = "8.8.8.8" }},
		{"empty domain", func(s *TaskSpec) { s.Domain = "" }},
		{"domain with credentials", func(s *TaskSpec) { s.Domain = "user@evil.example" }},
		{"domain with path traversal", func(s *TaskSpec) { s.Domain = "evil.example/../x" }},
		{"path without leading slash", func(s *TaskSpec) { s.Path = "evil" }},
		{"stale task replayed", func(s *TaskSpec) { s.IssuedAt = time.Now().Add(-1 * time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec()
			tc.mutate(&spec)
			if err := ValidateTask(spec); err == nil {
				t.Errorf("task was accepted but must be refused: %+v", spec)
			}
		})
	}
}

func TestIsPrivateOrReservedCoversTheDangerousRanges(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.5.4",
		"169.254.169.254", // cloud metadata — the classic SSRF pivot
		"100.64.0.1",      // CGNAT
		"0.0.0.0", "224.0.0.1",
		"::1", "fe80::1", "fd00::1",
	}
	for _, ip := range private {
		if !IsPrivateOrReserved(net.ParseIP(ip)) {
			t.Errorf("%s must be treated as private/reserved", ip)
		}
	}

	public := []string{"8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"}
	for _, ip := range public {
		if IsPrivateOrReserved(net.ParseIP(ip)) {
			t.Errorf("%s is public and must not be refused", ip)
		}
	}
}

func TestRateLimiterStopsAtTheHardCeiling(t *testing.T) {
	limiter := NewRateLimiter()
	for i := 0; i < MaxChecksPerMinute; i++ {
		if !limiter.Allow() {
			t.Fatalf("limiter refused check %d, below the ceiling of %d", i+1, MaxChecksPerMinute)
		}
	}
	if limiter.Allow() {
		t.Fatalf("limiter allowed check %d, above the ceiling of %d", MaxChecksPerMinute+1, MaxChecksPerMinute)
	}
}

func TestCooldownBlocksRepeatChecksOfOneTarget(t *testing.T) {
	cooldown := NewCooldown()
	if !cooldown.Allow("example.com") {
		t.Fatal("first check of a target must be allowed")
	}
	if cooldown.Allow("example.com") {
		t.Fatal("second check within the cooldown window must be refused")
	}
	if !cooldown.Allow("other.example") {
		t.Fatal("a different target must not be affected by another target's cooldown")
	}
}
