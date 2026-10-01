package provider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OpenCode Zen's anonymous free lane (key: the literal "public").
//
// A request passes only as the OpenCode CLI's own — descending "ses_"
// session ids, ascending "msg_" request ids, a bare "opencode/<version>"
// agent, stream:true, and tool declarations named "shell"/"bash" and
// "read" — or the gateway answers 403 FreeTierError ("can only be used
// from within OpenCode"). Verified against the CLI 1.18.30 binary and its
// sources (packages/opencode/src/id/id.ts, session/llm/request.ts); the
// sibling branch feat/opencode-zen-free-subscription proved the same set
// live (provider test answers on chat and Responses through the gateway).

// OpenCodeFreeKey is the literal credential the anonymous lane accepts.
const OpenCodeFreeKey = "public"

// OpenCodeCLIVersion mirrors the CLI release the User-Agent claims: the
// CLI sends a bare "opencode/<version>", no platform suffix.
const OpenCodeCLIVersion = "1.18.30"

const openCodeBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// IsOpenCodeFree reports whether the provider reaches OpenCode's gateway on
// the anonymous free lane: the literal "public" key, or no key at all (which
// the gateway also treats as anonymous, but without a Bearer it is turned
// away before the free-tier check).
func (p Provider) IsOpenCodeFree() bool {
	if !p.IsOpenCode() {
		return false
	}
	k := strings.TrimSpace(p.Key)
	return k == "" || k == OpenCodeFreeKey
}

// ---- CLI-shaped correlation ids -------------------------------------------
// Port of the CLI's identifier module: sessions are descending ids ("ses_"
// + low 6 bytes of ~(nowMs*0x1000+counter)), user messages ascending
// ("msg_" + low 6 bytes of nowMs*0x1000+counter), both followed by 14
// base62 chars. The lane's FreeTier gate validates these shapes — an
// ascending session or a "req_" request id is answered 403.

var (
	openCodeMu      sync.Mutex
	openCodeLastMs  int64
	openCodeCounter uint64
)

// openCodeNext is the process-wide per-millisecond counter, reset when the
// millisecond turns over, verbatim upstream.
func openCodeNext(nowMs int64) uint64 {
	openCodeMu.Lock()
	defer openCodeMu.Unlock()
	if nowMs != openCodeLastMs {
		openCodeLastMs, openCodeCounter = nowMs, 0
	}
	openCodeCounter++
	return openCodeCounter
}

// openCodeTimePart is the low 6 bytes of the counter value as 12 lowercase
// hex chars. descending mirrors the CLI's sessions (~n), ascending its
// messages (n).
func openCodeTimePart(nowMs int64, descending bool) string {
	v := uint64(nowMs)*0x1000 + openCodeNext(nowMs)
	if descending {
		v = ^v
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	const hexd = "0123456789abcdef"
	out := make([]byte, 12)
	for i, x := range b[2:] {
		out[i*2] = hexd[x>>4]
		out[i*2+1] = hexd[x&0xf]
	}
	return string(out)
}

// openCodeSuffix maps entropy bytes to 14 base62 chars, verbatim upstream.
func openCodeSuffix(entropy []byte) string {
	var sb strings.Builder
	for _, x := range entropy {
		if sb.Len() >= 14 {
			break
		}
		sb.WriteByte(openCodeBase62[int(x)%62])
	}
	return sb.String()
}

// OpenCodeSessionID is a CLI-shaped descending session id with a
// seed-stable suffix: one conversation keeps its trailing chars while the
// time part stays fresh.
func OpenCodeSessionID(seed string) string {
	sum := sha256.Sum256([]byte("ses" + "\x00" + seed))
	return "ses_" + openCodeTimePart(time.Now().UnixMilli(), true) + openCodeSuffix(sum[:])
}

// OpenCodeRequestID is a CLI-shaped ascending user-message id with a random
// suffix. Randomness failing must not fail the request, so it falls back
// to time.
func OpenCodeRequestID() string {
	var b [14]byte
	if _, err := rand.Read(b[:]); err != nil {
		sum := sha256.Sum256([]byte("msg" + "\x00" + fmt.Sprint(time.Now().UnixNano())))
		copy(b[:], sum[:])
	}
	return "msg_" + openCodeTimePart(time.Now().UnixMilli(), false) + openCodeSuffix(b[:])
}

// OpenCodeUserAgent is the CLI-identical user agent: bare
// "opencode/<version>".
func OpenCodeUserAgent() string {
	return "opencode/" + OpenCodeCLIVersion
}

// OpenCodeFreeIDs are the correlation ids for one upstream request on the
// anonymous lane: a descending session stable per conversation, and a fresh
// message id.
type OpenCodeFreeIDs struct {
	Session string
	Request string
}

// openCodeSeed is the conversation signal: the first user message's raw
// JSON. Using the first user turn keeps a multi-turn conversation stable as
// its history grows while separating conversations with different
// beginnings.
func openCodeSeed(body []byte) string {
	var m struct {
		Messages []json.RawMessage `json:"messages"`
		Input    json.RawMessage   `json:"input"`
		Contents []json.RawMessage `json:"contents"`
	}
	if json.Unmarshal(body, &m) != nil {
		if len(body) > 0 {
			return string(body)
		}
		return ""
	}
	items := m.Messages
	geminiContents := len(items) == 0 && len(m.Contents) > 0
	if geminiContents {
		items = m.Contents
	}
	if len(items) == 0 && len(m.Input) > 0 && m.Input[0] == '[' {
		_ = json.Unmarshal(m.Input, &items)
	}
	for _, it := range items {
		var r struct {
			Role string `json:"role"`
		}
		if json.Unmarshal(it, &r) == nil && (r.Role == "user" || (geminiContents && r.Role == "")) {
			return string(it)
		}
	}
	if len(items) > 0 {
		return string(items[0])
	}
	if len(m.Input) > 0 {
		return string(m.Input)
	}
	return string(body)
}

// OpenCodeFreeIDsFor derives the correlation ids for one upstream request.
func OpenCodeFreeIDsFor(seed string) OpenCodeFreeIDs {
	s := strings.TrimSpace(seed)
	if s == "" || s == "{}" {
		var b [14]byte
		_, _ = rand.Read(b[:])
		s = "fallback\x00" + string(b[:])
	}
	return OpenCodeFreeIDs{
		Session: OpenCodeSessionID(s),
		Request: OpenCodeRequestID(),
	}
}

// OpenCodeFreeHeaders is the disguise header set sent with every upstream
// request on the anonymous lane: exactly what the CLI sends for opencode
// providers (no affinity or project headers — those belong to other lanes).
func OpenCodeFreeHeaders(ids OpenCodeFreeIDs) map[string]string {
	return map[string]string{
		"User-Agent":         OpenCodeUserAgent(),
		"x-opencode-client":  "cli",
		"x-opencode-session": ids.Session,
		"x-opencode-request": ids.Request,
	}
}

// DisguiseRequest applies the CLI-identical auth and header set for the
// anonymous free lane onto an outbound upstream request. body is the (tool-
// prepared) request body, for the derived ids. A missing Authorization
// becomes Bearer public.
func (p Provider) DisguiseRequest(req *http.Request, body []byte) {
	ids := OpenCodeFreeIDsFor(openCodeSeed(body))
	for k, v := range OpenCodeFreeHeaders(ids) {
		req.Header.Set(k, v)
	}
	if strings.TrimSpace(req.Header.Get("Authorization")) == "" {
		req.Header.Set("Authorization", "Bearer "+OpenCodeFreeKey)
	}
}

// ---- request body gate ------------------------------------------------------
// The lane additionally requires stream:true and tool declarations named
// "shell"/"bash" and "read" (case-insensitive): without them even a
// header-perfect request is answered 403. Real agent turns carry tools;
// freeLanePrepare adds stub declarations when none usable are there, so
// probes and tool-less calls (titles, classifiers) pass the gate too. A
// model calling a stub the client never defined gets the client's error,
// as with any unknown tool.

// freeLaneToolNames lists a request's tool names in lower case, whatever
// protocol shape they come in (chat, responses or Anthropic).
func freeLaneToolNames(body []byte) []string {
	var v struct {
		Tools []struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Function *struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var out []string
	for _, t := range v.Tools {
		name := t.Name
		if t.Function != nil && t.Function.Name != "" {
			name = t.Function.Name
		}
		if name != "" {
			out = append(out, strings.ToLower(name))
		}
	}
	return out
}

// freeLaneHasGateTools reports whether the body declares the tools the gate
// wants: a shell ("shell" or "bash") and "read".
func freeLaneHasGateTools(body []byte) bool {
	var shell, read bool
	for _, n := range freeLaneToolNames(body) {
		switch n {
		case "shell", "bash":
			shell = true
		case "read":
			read = true
		}
	}
	return shell && read
}

// freeLanePrepare returns body with the gate's stub tools added when it has
// none usable, in the shape matching the body's own protocol. Bodies that
// already pass, or aren't JSON chat/Responses requests, go through
// untouched.
func freeLanePrepare(body []byte) []byte {
	if freeLaneHasGateTools(body) {
		return body
	}
	var v map[string]any
	if json.Unmarshal(body, &v) != nil {
		return body
	}
	_, isChat := v["messages"]
	_, isResponses := v["input"]
	if !isChat && !isResponses {
		return body
	}
	shell := map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}}
	read := map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}}
	var tools []any
	if isResponses {
		tools = []any{
			map[string]any{"type": "function", "name": "shell", "description": "Run a shell command", "parameters": shell},
			map[string]any{"type": "function", "name": "read", "description": "Read a file", "parameters": read},
		}
	} else {
		tools = []any{
			map[string]any{"type": "function", "function": map[string]any{"name": "shell", "description": "Run a shell command", "parameters": shell}},
			map[string]any{"type": "function", "function": map[string]any{"name": "read", "description": "Read a file", "parameters": read}},
		}
	}
	if old, ok := v["tools"].([]any); ok {
		tools = append(old, tools...)
	}
	v["tools"] = tools
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return out
}

// freeLaneTiny is the smallest probe of model on proto: streamed, with the
// gate's tools, so `provider test` exercises the lane rather than its gate.
func freeLaneTiny(q Provider, proto Protocol, model string) (url, body string) {
	shell := `{"type":"object","properties":{"command":{"type":"string"}}}`
	read := `{"type":"object","properties":{"path":{"type":"string"}}}`
	if proto == Responses {
		return q.Responses + "/responses", fmt.Sprintf(`{"model":%q,"input":"hi","stream":true,"max_output_tokens":16,"tools":[{"type":"function","name":"shell","description":"Run a shell command","parameters":%s},{"type":"function","name":"read","description":"Read a file","parameters":%s}]}`,
			model, shell, read)
	}
	return q.Chat + "/chat/completions", fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":16,"tools":[{"type":"function","function":{"name":"shell","description":"Run a shell command","parameters":%s}},{"type":"function","function":{"name":"read","description":"Read a file","parameters":%s}}]}`,
		model, shell, read)
}
