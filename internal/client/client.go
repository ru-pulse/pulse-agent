// Package client talks to the control plane.
//
// Every request after registration carries an Ed25519 signature made with the
// agent's own key, so there is no bearer token sitting on a partner's disk for
// somebody to steal, and knowing an agent ID is not enough to impersonate it.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/identity"
	"github.com/ru-pulse/pulse-agent/internal/protocol"
)

type Client struct {
	baseURL  string
	identity *identity.Identity
	version  string
	http     *http.Client
}

func New(baseURL string, id *identity.Identity, version string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		identity: id,
		version:  version,
		// Comfortably longer than the server's long-poll window so a held
		// connection is never cut client-side mid-wait.
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

type registerResponse struct {
	AgentID         string `json:"agentId"`
	ServerPubkeyPEM string `json:"serverPubkeyPem"`
}

type pubkeyResponse struct {
	PubkeyPEM string `json:"pubkeyPem"`
}

type pollResponse struct {
	Tasks []protocol.Task `json:"tasks"`
}

// Status — то, что control plane знает об этом агенте. Тот же ответ будет
// показывать окно приложения.
type Status struct {
	BoundToPartner bool   `json:"boundToPartner"`
	PartnerEmail   string `json:"partnerEmail"`
	Reputation     int    `json:"reputation"`
	ChecksServed   int64  `json:"checksServed"`
	VPNSuspect     bool   `json:"vpnSuspect"`
	VPNReason      string `json:"vpnReason"`
	Blocked        bool   `json:"blocked"`
	// Counted — засчитываются ли результаты этого агента сетью. Если нет,
	// NotCountedReason объясняет причину словами.
	Counted          bool   `json:"counted"`
	NotCountedReason string `json:"notCountedReason"`
	Network          struct {
		Group   string `json:"group"`
		ASN     int    `json:"asn"`
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"network"`
}

// APIError несёт код ответа и машинночитаемую причину, чтобы вызывающий мог
// отличить «неверный код партнёра» от сетевого сбоя и не советовал человеку
// проверить интернет, когда у него опечатка в коде.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Code)
}

func IsUnknownPartnerCode(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == "unknown_partner_code"
}

func (c *Client) Register(ctx context.Context, claimedCity, partnerCode string) error {
	body := map[string]any{
		"pubkeyPem":    c.identity.File.PublicKeyPEM,
		"agentVersion": c.version,
	}
	if claimedCity != "" {
		body["claimedCity"] = claimedCity
	}
	if partnerCode != "" {
		body["partnerCode"] = partnerCode
	}

	var parsed registerResponse
	if err := c.postJSON(ctx, "/api/v1/agents/register", body, &parsed); err != nil {
		return err
	}
	if parsed.AgentID == "" || parsed.ServerPubkeyPEM == "" {
		return fmt.Errorf("registration response missing agentId or server key")
	}

	c.identity.File.AgentID = parsed.AgentID
	if err := c.identity.PinServerKey(parsed.ServerPubkeyPEM); err != nil {
		return fmt.Errorf("pinning server key: %w", err)
	}
	return nil
}

// VerifyPinnedServerKey re-fetches the control plane's public key and compares
// it with the one pinned at registration. A change means the server was
// replaced or someone is in the middle — either way, not something to keep
// running against silently.
func (c *Client) VerifyPinnedServerKey(ctx context.Context) error {
	var parsed pubkeyResponse
	if err := c.getJSON(ctx, "/api/v1/server/pubkey", &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.PubkeyPEM) != strings.TrimSpace(c.identity.File.PinnedServerKeyPEM) {
		return fmt.Errorf("server key changed since first run (pinned in %s)", c.identity.Path)
	}
	return nil
}

func (c *Client) Poll(ctx context.Context) ([]protocol.Task, error) {
	nonce, err := protocol.Nonce()
	if err != nil {
		return nil, err
	}
	ts := time.Now().UnixMilli()
	payload := map[string]any{
		"agentId": c.identity.File.AgentID,
		"ts":      ts,
		"nonce":   nonce,
	}
	sig, err := protocol.Sign(c.identity.PrivateKey, payload)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("agent_id", c.identity.File.AgentID)
	query.Set("ts", strconv.FormatInt(ts, 10))
	query.Set("nonce", nonce)
	query.Set("sig", sig)

	var parsed pollResponse
	if err := c.getJSON(ctx, "/api/v1/agents/poll?"+query.Encode(), &parsed); err != nil {
		return nil, err
	}
	return parsed.Tasks, nil
}

// SubmitResults signs and sends a batch. The `results` value passed here is
// the exact value that gets serialised, so what is signed and what is sent
// can never drift apart.
func (c *Client) SubmitResults(ctx context.Context, results []map[string]any) error {
	nonce, err := protocol.Nonce()
	if err != nil {
		return err
	}
	payload := map[string]any{
		"agentId": c.identity.File.AgentID,
		"ts":      time.Now().UnixMilli(),
		"nonce":   nonce,
		"results": results,
	}
	sig, err := protocol.Sign(c.identity.PrivateKey, payload)
	if err != nil {
		return err
	}

	body := map[string]any{
		"agentId": payload["agentId"],
		"ts":      payload["ts"],
		"nonce":   payload["nonce"],
		"results": results,
		"sig":     sig,
	}
	return c.postJSON(ctx, "/api/v1/agents/results", body, nil)
}

// Bind привязывает уже зарегистрированного агента к партнёру. Это путь для
// того, кто установил агента и забыл ввести код: личность агента, репутация и
// история канареек при этом сохраняются.
func (c *Client) Bind(ctx context.Context, partnerCode string) error {
	nonce, err := protocol.Nonce()
	if err != nil {
		return err
	}
	payload := map[string]any{
		"agentId":     c.identity.File.AgentID,
		"ts":          time.Now().UnixMilli(),
		"nonce":       nonce,
		"partnerCode": partnerCode,
	}
	sig, err := protocol.Sign(c.identity.PrivateKey, payload)
	if err != nil {
		return err
	}
	body := map[string]any{}
	for k, v := range payload {
		body[k] = v
	}
	body["sig"] = sig
	return c.postJSON(ctx, "/api/v1/agent/bind", body, nil)
}

func (c *Client) Status(ctx context.Context) (*Status, error) {
	nonce, err := protocol.Nonce()
	if err != nil {
		return nil, err
	}
	ts := time.Now().UnixMilli()
	payload := map[string]any{"agentId": c.identity.File.AgentID, "ts": ts, "nonce": nonce}
	sig, err := protocol.Sign(c.identity.PrivateKey, payload)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("agent_id", c.identity.File.AgentID)
	query.Set("ts", strconv.FormatInt(ts, 10))
	query.Set("nonce", nonce)
	query.Set("sig", sig)

	var status Status
	if err := c.getJSON(ctx, "/api/v1/agent/status?"+query.Encode(), &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &parsed) == nil && parsed.Error != "" {
			apiErr.Code = parsed.Error
			apiErr.Message = parsed.Message
		} else {
			apiErr.Message = strings.TrimSpace(string(data))
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
