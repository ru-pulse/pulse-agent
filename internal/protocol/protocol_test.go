package protocol

import (
	"testing"
)

// Golden values produced by the Node implementation
// (control-plane/src/lib/protocol.js). If a change here makes these fail,
// every signature between the agent and the control plane would silently stop
// verifying — fix the code, not the fixtures, unless both sides change together.
//
// The keypair below is a TEST FIXTURE with a deliberately fixed seed (every
// byte 0x07) so both implementations can be compared against a known
// signature. It is public by design and must never be used anywhere real.
const (
	nodePublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=\n" +
		"-----END PUBLIC KEY-----\n"
	nodePrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n" +
		"-----END PRIVATE KEY-----\n"

	canonicalTask = `{"domain":"пример.рф","expectedStatus":200,"id":"11111111-2222-3333-4444-555555555555",` +
		`"issuedAt":1788811114417,"kind":"monitor","method":"GET",` +
		`"monitorId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","nonce":"0123456789abcdef01234567",` +
		`"path":"/a?b=1&c=<2>","port":443,"scheme":"https"}`

	canonicalCanary = `{"domain":"пример.рф","expectedStatus":200,"id":"11111111-2222-3333-4444-555555555555",` +
		`"issuedAt":1788811114417,"kind":"canary","method":"GET","monitorId":null,` +
		`"nonce":"0123456789abcdef01234567","path":"/a?b=1&c=<2>","port":443,"scheme":"https"}`

	nodeSignatureOfTask = "hs71XatABoOBcPEzGiUJIC2Jd5G6012kmpsH/GcBoLk0M99YGgXTYqAbsLzzZynOq0x2FB/8mCuB4+lmHFXDDA=="
)

func sampleTask(kind string, monitorID any) Task {
	return Task{
		ID:             "11111111-2222-3333-4444-555555555555",
		Kind:           kind,
		MonitorID:      monitorID,
		Domain:         "пример.рф",
		Port:           443,
		Scheme:         "https",
		Path:           "/a?b=1&c=<2>",
		Method:         "GET",
		ExpectedStatus: 200,
		IssuedAt:       1788811114417,
		Nonce:          "0123456789abcdef01234567",
	}
}

func TestCanonicalMatchesNode(t *testing.T) {
	cases := []struct {
		name string
		task Task
		want string
	}{
		{"monitor task", sampleTask("monitor", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), canonicalTask},
		{"canary task with null monitorId", sampleTask("canary", nil), canonicalCanary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.task.SignedPayload())
			if err != nil {
				t.Fatalf("Canonical() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("canonical JSON diverged from the Node implementation\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// The real thing this protects: a task signed by the Node control plane must
// verify in the Go agent.
func TestVerifiesNodeSignature(t *testing.T) {
	pub, err := ParsePublicKeyPEM(nodePublicKeyPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	task := sampleTask("monitor", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	if !Verify(pub, task.SignedPayload(), nodeSignatureOfTask) {
		t.Fatal("signature produced by the Node control plane failed to verify in Go")
	}
	tampered := task
	tampered.Domain = "evil.example"
	if Verify(pub, tampered.SignedPayload(), nodeSignatureOfTask) {
		t.Fatal("a tampered task verified — signature check is not covering the payload")
	}
}

// ...and a payload signed by the Go agent must produce the byte-identical
// signature the Node side would, given the same key.
func TestGoSignatureMatchesNode(t *testing.T) {
	priv, err := ParsePrivateKeyPEM(nodePrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	got, err := Sign(priv, sampleTask("monitor", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").SignedPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != nodeSignatureOfTask {
		t.Errorf("Go signature differs from Node's\n got: %s\nwant: %s", got, nodeSignatureOfTask)
	}
}

func TestCanonicalNumbersArePrintedLikeJavaScript(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{int64(1788811114417), "1788811114417"},
		{float64(1788811114417), "1788811114417"}, // not 1.788811114417e+12
		{float64(443), "443"},
		{0.5, "0.5"},
		{nil, "null"},
		{true, "true"},
		{[]any{int64(1), "a", nil}, `[1,"a",null]`},
	}
	for _, tc := range cases {
		got, err := Canonical(tc.value)
		if err != nil {
			t.Fatalf("Canonical(%v): %v", tc.value, err)
		}
		if got != tc.want {
			t.Errorf("Canonical(%v) = %s, want %s", tc.value, got, tc.want)
		}
	}
}
