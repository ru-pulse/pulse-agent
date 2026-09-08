// Package checker runs one staged availability check.
//
// The stages are deliberately separate — DNS, TCP, TLS, HTTP — because *where*
// a connection dies is the diagnosis: a poisoned DNS answer, an IP-level
// block, SNI-based DPI, or nothing wrong at all. A plain "site is down" would
// throw that information away.
//
// The response body is never stored or transmitted: reading stops at the
// status line. That is what keeps this agent from being usable as a scraper.
package checker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/guardrails"
)

const (
	stageTimeout = 8 * time.Second
	maxReadBytes = 8 * 1024
)

// Result is the entire payload that leaves the partner's machine for one
// check. Nothing about the host, the network, or the response content is here.
type Result struct {
	Stage      string // ok | dns | tcp | tls | http
	ErrorCode  string
	HTTPStatus int
	DNSMs      int64
	TCPMs      int64
	TLSMs      int64
	HTTPMs     int64
	ResolvedIP string

	// BytesIn/BytesOut считаются на сокете, то есть включают рукопожатие TLS.
	// Наружу не отправляются — нужны, чтобы показать партнёру, сколько его
	// трафика реально потрачено. «Съест ли это мой интернет» — первый вопрос
	// человека, ставящего такую программу, и отвечать на него надо цифрой.
	BytesIn  int64
	BytesOut int64
}

// countingConn считает байты на уровне сокета, до TLS: только так в счёт
// попадает и рукопожатие, а не одни лишь данные HTTP.
type countingConn struct {
	net.Conn
	in  int64
	out int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(&c.in, int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(&c.out, int64(n))
	return n, err
}

type Target struct {
	Domain string
	Port   int
	Scheme string
	Path   string
	Method string
}

func Run(ctx context.Context, target Target) (result Result) {
	dnsStart := time.Now()
	ip, err := guardrails.ResolvePublicAddr(ctx, target.Domain)
	if err != nil {
		return Result{Stage: "dns", ErrorCode: classify(err), DNSMs: sinceMs(dnsStart)}
	}
	dnsMs := sinceMs(dnsStart)

	tcpStart := time.Now()
	dialer := net.Dialer{Timeout: stageTimeout}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(target.Port))
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Result{Stage: "tcp", ErrorCode: classify(err), DNSMs: dnsMs, ResolvedIP: ip.String()}
	}
	counter := &countingConn{Conn: rawConn}
	var conn net.Conn = counter
	defer conn.Close()
	tcpMs := sinceMs(tcpStart)

	result = Result{DNSMs: dnsMs, TCPMs: tcpMs, ResolvedIP: ip.String()}
	// Байты доносятся до вызывающего при любом исходе, включая обрыв на TLS:
	// потраченный трафик надо показать и тогда, когда проверка не удалась.
	defer func() {
		result.BytesIn = atomic.LoadInt64(&counter.in)
		result.BytesOut = atomic.LoadInt64(&counter.out)
	}()

	if target.Scheme == "https" {
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: target.Domain, MinVersion: tls.VersionTLS12})
		_ = tlsConn.SetDeadline(time.Now().Add(stageTimeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			result.Stage = "tls"
			result.ErrorCode = classify(err)
			return result
		}
		result.TLSMs = sinceMs(tlsStart)
		conn = tlsConn
	}

	httpStart := time.Now()
	status, err := requestStatus(conn, target)
	if err != nil {
		result.Stage = "http"
		result.ErrorCode = classify(err)
		return result
	}
	result.HTTPMs = sinceMs(httpStart)
	result.HTTPStatus = status
	result.Stage = "ok"
	return result
}

// requestStatus writes a minimal HTTP/1.1 request and reads exactly the status
// line. Connection: close plus an early return means the body is never pulled.
func requestStatus(conn net.Conn, target Target) (int, error) {
	if err := conn.SetDeadline(time.Now().Add(stageTimeout)); err != nil {
		return 0, err
	}
	request := fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: pulse-agent/1.0 (+https://github.com/pulse-runeta)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		target.Method, target.Path, target.Domain,
	)
	if _, err := conn.Write([]byte(request)); err != nil {
		return 0, err
	}

	reader := bufio.NewReaderSize(conn, maxReadBytes)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
		return 0, fmt.Errorf("unparseable status line")
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("unparseable status code")
	}
	return status, nil
}

func sinceMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func classify(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "DNS_NXDOMAIN"
		}
		if dnsErr.IsTimeout {
			return "DNS_TIMEOUT"
		}
		return "DNS_ERROR"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "TIMEOUT"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refusing private"):
		return "REFUSED_PRIVATE_TARGET"
	case strings.Contains(msg, "connection refused"):
		return "CONN_REFUSED"
	case strings.Contains(msg, "connection reset"):
		return "CONN_RESET"
	case strings.Contains(msg, "certificate"):
		return "TLS_CERT_ERROR"
	case strings.Contains(msg, "handshake"), strings.Contains(msg, "tls:"):
		return "TLS_ERROR"
	case strings.Contains(msg, "no route to host"):
		return "NO_ROUTE"
	case strings.Contains(msg, "EOF"):
		return "EOF"
	default:
		return "UNKNOWN"
	}
}
