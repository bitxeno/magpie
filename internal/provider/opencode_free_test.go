package provider

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

var openCodeBodyPattern = regexp.MustCompile(`^[0-9a-f]{12}[0-9A-Za-z]{14}$`)

func openCodeBody(id string) string {
	if i := strings.IndexByte(id, '_'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func TestOpenCodeSessionIsDescending(t *testing.T) {
	// Descending ids sort below their time's ascending ones: the high bits
	// are inverted (~n), so a descending body starts above 0x7fff….
	a := OpenCodeSessionID("hello")
	if !strings.HasPrefix(a, "ses_") || !openCodeBodyPattern.MatchString(openCodeBody(a)) {
		t.Fatalf("shape: %q", a)
	}
	// Descending (~n): the leading hex sits above the ascending range.
	if c := openCodeBody(a)[0]; c < '8' {
		t.Fatalf("session not descending: %q", a)
	}
	b := OpenCodeSessionID("hello")
	// Only the suffix is stable; the time part stays fresh.
	if openCodeBody(a)[12:] != openCodeBody(b)[12:] {
		t.Fatalf("suffix not stable: %q %q", a, b)
	}
	if a == b {
		t.Fatalf("time part should stay fresh: %q", a)
	}
	if openCodeBody(OpenCodeSessionID("world"))[12:] == openCodeBody(a)[12:] {
		t.Fatalf("different seeds share suffix")
	}
}

func TestOpenCodeRequestIsAscendingMessage(t *testing.T) {
	a := OpenCodeRequestID()
	b := OpenCodeRequestID()
	if !strings.HasPrefix(a, "msg_") || !openCodeBodyPattern.MatchString(openCodeBody(a)) {
		t.Fatalf("shape: %q", a)
	}
	if a == b {
		t.Fatalf("request not random")
	}
}

func TestOpenCodeFreeIDsCorrelated(t *testing.T) {
	seed := `{"role":"user","content":"hi"}`
	first := OpenCodeFreeIDsFor(seed)
	second := OpenCodeFreeIDsFor(seed)
	if openCodeBody(first.Session)[12:] != openCodeBody(second.Session)[12:] {
		t.Fatalf("same seed, different session suffix: %q %q", first.Session, second.Session)
	}
	if first.Request == second.Request {
		t.Fatalf("request not random")
	}
	for _, id := range []string{first.Session, first.Request} {
		if !openCodeBodyPattern.MatchString(openCodeBody(id)) {
			t.Fatalf("shape: %q", id)
		}
	}
}

func TestIsOpenCodeFree(t *testing.T) {
	zen := "https://opencode.ai/zen/v1"
	if !((Provider{Chat: zen, Key: "public"}).IsOpenCodeFree()) {
		t.Fatalf("public key should be free")
	}
	if !((Provider{Chat: zen, Key: ""}).IsOpenCodeFree()) {
		t.Fatalf("empty key should be free")
	}
	if (Provider{Chat: zen, Key: "sk-real"}).IsOpenCodeFree() {
		t.Fatalf("real key should not be free")
	}
	if (Provider{Chat: "https://api.openai.com/v1", Key: "public"}).IsOpenCodeFree() {
		t.Fatalf("other hosts should not be free")
	}
}

func TestOpenCodeFreeHeaders(t *testing.T) {
	ids := OpenCodeFreeIDsFor("seed-1")
	h := OpenCodeFreeHeaders(ids)
	// Bare agent, exactly what the CLI sends for opencode providers.
	if h["User-Agent"] != "opencode/"+OpenCodeCLIVersion {
		t.Fatalf("UA: %q", h["User-Agent"])
	}
	if h["x-opencode-client"] != "cli" {
		t.Fatalf("client: %v", h)
	}
	if h["x-opencode-session"] != ids.Session {
		t.Fatalf("session: %v", h)
	}
	if h["x-opencode-request"] != ids.Request {
		t.Fatalf("request: %v", h)
	}
	if len(h) != 4 {
		t.Fatalf("exactly the CLI's set, got %v", h)
	}
}

func TestFreeLanePrepareAddsGateTools(t *testing.T) {
	bare := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	out := freeLanePrepare([]byte(bare))
	if string(out) == bare {
		t.Fatalf("stub tools not added")
	}
	if !freeLaneHasGateTools(out) {
		t.Fatalf("gate tools missing: %s", out)
	}
	// Bodies that already pass go through untouched.
	again := freeLanePrepare(out)
	if string(again) != string(out) {
		t.Fatalf("passing body rewritten")
	}
	// Non-JSON and non-chat bodies go through untouched.
	for _, b := range []string{"not json", `{"foo":1}`, `{"model":"m"}`} {
		if got := freeLanePrepare([]byte(b)); string(got) != b {
			t.Fatalf("touched %q: %q", b, got)
		}
	}
}

func TestFreeLaneTinyStreamsWithTools(t *testing.T) {
	q := Provider{ID: "x", Chat: "https://opencode.ai/zen/v1", Responses: "https://opencode.ai/zen/v1"}
	for _, proto := range []Protocol{Chat, Responses} {
		url, body := freeLaneTiny(q, proto, "mimo-v2.6-flash-free")
		if url == "" || body == "" {
			t.Fatalf("%s: empty probe", proto)
		}
		var v map[string]any
		if json.Unmarshal([]byte(body), &v) != nil {
			t.Fatalf("%s: not JSON: %s", proto, body)
		}
		if v["stream"] != true {
			t.Fatalf("%s: not streamed: %s", proto, body)
		}
		if !freeLaneHasGateTools([]byte(body)) {
			t.Fatalf("%s: no gate tools: %s", proto, body)
		}
	}
}
