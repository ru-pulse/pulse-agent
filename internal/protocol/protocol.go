// Package protocol implements the wire format shared with the control plane
// (control-plane/src/lib/protocol.js).
//
// Signatures are Ed25519 over a canonical JSON encoding: object keys sorted,
// no whitespace, numbers printed the way JavaScript prints them. The
// JavaScript side canonicalises the *parsed* request body, so what matters is
// that both sides agree on the set of fields and their values — not on the
// order they happen to appear on the wire.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxClockSkew must match MAX_CLOCK_SKEW_MS on the server.
const MaxClockSkew = 5 * time.Minute

var (
	AllowedMethods = []string{"GET", "HEAD"}
	AllowedPorts   = []int{80, 443}
)

// Task is a single check assignment, signed by the control plane.
type Task struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	MonitorID      any    `json:"monitorId"`
	Domain         string `json:"domain"`
	Port           int    `json:"port"`
	Scheme         string `json:"scheme"`
	Path           string `json:"path"`
	Method         string `json:"method"`
	ExpectedStatus int    `json:"expectedStatus"`
	IssuedAt       int64  `json:"issuedAt"`
	Nonce          string `json:"nonce"`
	Sig            string `json:"sig"`
}

// SignedPayload rebuilds exactly the object the server signed: every task
// field except the signature itself.
func (t Task) SignedPayload() map[string]any {
	return map[string]any{
		"id":             t.ID,
		"kind":           t.Kind,
		"monitorId":      t.MonitorID,
		"domain":         t.Domain,
		"port":           t.Port,
		"scheme":         t.Scheme,
		"path":           t.Path,
		"method":         t.Method,
		"expectedStatus": t.ExpectedStatus,
		"issuedAt":       t.IssuedAt,
		"nonce":          t.Nonce,
	}
}

// Canonical renders v the way control-plane/src/lib/protocol.js canonicalize()
// does. Keep the two in lockstep: a mismatch here shows up as every signature
// failing to verify.
func Canonical(v any) (string, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeCanonical(sb *strings.Builder, v any) error {
	switch value := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(value))
	case string:
		encoded, err := encodeJSONString(value)
		if err != nil {
			return err
		}
		sb.WriteString(encoded)
	case int:
		sb.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		sb.WriteString(strconv.FormatInt(value, 10))
	case float64:
		sb.WriteString(formatNumber(value))
	case json.Number:
		sb.WriteString(value.String())
	case []any:
		sb.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case []map[string]any:
		items := make([]any, len(value))
		for i, item := range value {
			items[i] = item
		}
		return writeCanonical(sb, items)
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			encoded, err := encodeJSONString(key)
			if err != nil {
				return err
			}
			sb.WriteString(encoded)
			sb.WriteByte(':')
			if err := writeCanonical(sb, value[key]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("protocol: unsupported type %T in canonical JSON", v)
	}
	return nil
}

// JavaScript has one number type, so an integral value always prints without
// a decimal point or exponent. Go's default float formatting does not.
func formatNumber(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "null"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// encodeJSONString matches JSON.stringify: no HTML escaping of < > &.
func encodeJSONString(s string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func Sign(priv ed25519.PrivateKey, payload any) (string, error) {
	canonical, err := Canonical(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical))), nil
}

func Verify(pub ed25519.PublicKey, payload any, signatureB64 string) bool {
	canonical, err := Canonical(payload)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(canonical), sig)
}

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func MarshalPublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func ParsePublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("protocol: no PEM block in public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("protocol: expected an Ed25519 public key, got %T", parsed)
	}
	return pub, nil
}

func ParsePrivateKeyPEM(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("protocol: no PEM block in private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("protocol: expected an Ed25519 private key, got %T", parsed)
	}
	return priv, nil
}

func Nonce() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}
