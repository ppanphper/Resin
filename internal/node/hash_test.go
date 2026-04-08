package node

import (
	"testing"
)

func TestHashFromRawOptions_Deterministic(t *testing.T) {
	raw := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":443,"method":"aes-256-gcm","password":"secret"}`)
	h1 := HashFromRawOptions(raw)
	h2 := HashFromRawOptions(raw)
	if h1 != h2 {
		t.Fatalf("same input produced different hashes: %s vs %s", h1.Hex(), h2.Hex())
	}
	if h1.IsZero() {
		t.Fatal("hash should not be zero for valid input")
	}
}

func TestHashFromRawOptions_IgnoresTag(t *testing.T) {
	withTag := []byte(`{"type":"shadowsocks","tag":"us-node-1","server":"1.2.3.4","server_port":443}`)
	withoutTag := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":443}`)
	differentTag := []byte(`{"type":"shadowsocks","tag":"jp-node-2","server":"1.2.3.4","server_port":443}`)

	h1 := HashFromRawOptions(withTag)
	h2 := HashFromRawOptions(withoutTag)
	h3 := HashFromRawOptions(differentTag)

	if h1 != h2 {
		t.Fatalf("tag should be ignored: with-tag=%s, without-tag=%s", h1.Hex(), h2.Hex())
	}
	if h1 != h3 {
		t.Fatalf("different tags should produce same hash: %s vs %s", h1.Hex(), h3.Hex())
	}
}

func TestHashFromRawOptions_DifferentConfigs(t *testing.T) {
	a := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":443}`)
	b := []byte(`{"type":"shadowsocks","server":"5.6.7.8","server_port":443}`)

	ha := HashFromRawOptions(a)
	hb := HashFromRawOptions(b)
	if ha == hb {
		t.Fatal("different configs should produce different hashes")
	}
}

func TestHashFromRawOptions_DifferentPortNotMerged(t *testing.T) {
	a := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":443,"method":"aes-256-gcm","password":"secret"}`)
	b := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":8443,"method":"aes-256-gcm","password":"secret"}`)

	ha := HashFromRawOptions(a)
	hb := HashFromRawOptions(b)
	if ha == hb {
		t.Fatal("same server with different port should not be merged")
	}
}

func TestHashFromRawOptions_DifferentProtocolNotMerged(t *testing.T) {
	httpNode := []byte(`{"type":"http","server":"example.com","server_port":8080,"username":"u","password":"p"}`)
	socksNode := []byte(`{"type":"socks","server":"example.com","server_port":8080,"username":"u","password":"p"}`)

	hHTTP := HashFromRawOptions(httpNode)
	hSOCKS := HashFromRawOptions(socksNode)
	if hHTTP == hSOCKS {
		t.Fatal("same endpoint with different protocol should not be merged")
	}
}

func TestHashFromRawOptions_VMessMissingAlterIDMatchesZero(t *testing.T) {
	withoutAlterID := []byte(`{"type":"vmess","server":"Example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto"}`)
	withZeroAlterID := []byte(`{"type":"vmess","server":"example.com","server_port":"443","uuid":"11111111-2222-3333-4444-555555555555","security":"auto","alter_id":0}`)

	h1 := HashFromRawOptions(withoutAlterID)
	h2 := HashFromRawOptions(withZeroAlterID)
	if h1 != h2 {
		t.Fatalf("vmess alter_id default mismatch: %s vs %s", h1.Hex(), h2.Hex())
	}
}

func TestHashFromRawOptions_IgnoresDialFields(t *testing.T) {
	base := []byte(`{"type":"vmess","server":"example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto","alter_id":0}`)
	withDialFields := []byte(`{"type":"vmess","server":"example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto","alter_id":0,"detour":"chain-a","bind_interface":"eth0","routing_mark":"0x20","tcp_fast_open":true}`)

	h1 := HashFromRawOptions(base)
	h2 := HashFromRawOptions(withDialFields)
	if h1 == h2 {
		return
	}
	// If this assertion fails, dedup will treat same upstream node from
	// different subscriptions as separate entries only because local dial fields differ.
	t.Fatalf("dial-only fields should not affect hash: %s vs %s", h1.Hex(), h2.Hex())
}

func TestHashFromRawOptions_TrojanImplicitTLSMatchesExplicitTLS(t *testing.T) {
	implicitTLS := []byte(`{"type":"trojan","server":"example.com","server_port":443,"password":"secret"}`)
	explicitTLS := []byte(`{"type":"trojan","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true,"server_name":"example.com"}}`)

	h1 := HashFromRawOptions(implicitTLS)
	h2 := HashFromRawOptions(explicitTLS)
	if h1 != h2 {
		t.Fatalf("trojan implicit/explicit tls should match: %s vs %s", h1.Hex(), h2.Hex())
	}
}

func TestHashFromRawOptions_DifferentTransportNotMerged(t *testing.T) {
	wsA := []byte(`{"type":"vmess","server":"example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto","alter_id":0,"transport":{"type":"ws","path":"/a"}}`)
	wsB := []byte(`{"type":"vmess","server":"example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","security":"auto","alter_id":0,"transport":{"type":"ws","path":"/b"}}`)

	h1 := HashFromRawOptions(wsA)
	h2 := HashFromRawOptions(wsB)
	if h1 == h2 {
		t.Fatal("different transport params should not be merged")
	}
}

func TestHashFromRawOptions_UnknownProtocol_GenericDedupIgnoresPresentationFields(t *testing.T) {
	a := []byte(`{
		"type":"my-new-proto",
		"tag":"node-a",
		"server":"EXAMPLE.com",
		"port":"443",
		"token":"secret",
		"detour":"chain-a",
		"bind_interface":"eth0"
	}`)
	b := []byte(`{
		"type":"my-new-proto",
		"tag":"node-b",
		"server":"example.com",
		"server_port":443,
		"token":"secret",
		"detour":"chain-b",
		"routing_mark":"0x20"
	}`)

	ha := HashFromRawOptions(a)
	hb := HashFromRawOptions(b)
	if ha != hb {
		t.Fatalf("unknown protocol generic dedup mismatch: %s vs %s", ha.Hex(), hb.Hex())
	}
}

func TestHashFromRawOptions_UnknownProtocol_DifferentIdentityNotMerged(t *testing.T) {
	a := []byte(`{"type":"my-new-proto","server":"example.com","server_port":443,"token":"secret-a"}`)
	b := []byte(`{"type":"my-new-proto","server":"example.com","server_port":443,"token":"secret-b"}`)

	ha := HashFromRawOptions(a)
	hb := HashFromRawOptions(b)
	if ha == hb {
		t.Fatal("unknown protocol with different identity fields should not be merged")
	}
}

func TestHashFromRawOptions_KeyOrderIndependent(t *testing.T) {
	a := []byte(`{"type":"shadowsocks","server":"1.2.3.4","server_port":443}`)
	b := []byte(`{"server_port":443,"server":"1.2.3.4","type":"shadowsocks"}`)

	ha := HashFromRawOptions(a)
	hb := HashFromRawOptions(b)
	if ha != hb {
		t.Fatalf("key order should not affect hash: %s vs %s", ha.Hex(), hb.Hex())
	}
}

func TestHashFromRawOptions_InvalidJSON_Fallback(t *testing.T) {
	raw := []byte(`not valid json`)
	h := HashFromRawOptions(raw)
	if h.IsZero() {
		t.Fatal("invalid JSON should still produce a non-zero hash via fallback")
	}

	// Fallback should be deterministic.
	h2 := HashFromRawOptions(raw)
	if h != h2 {
		t.Fatalf("fallback hash not deterministic: %s vs %s", h.Hex(), h2.Hex())
	}
}

func TestHexRoundTrip(t *testing.T) {
	raw := []byte(`{"type":"vmess","server":"example.com"}`)
	original := HashFromRawOptions(raw)

	hexStr := original.Hex()
	if len(hexStr) != 32 {
		t.Fatalf("hex string should be 32 chars, got %d: %s", len(hexStr), hexStr)
	}

	parsed, err := ParseHex(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != original {
		t.Fatalf("round-trip failed: %s != %s", parsed.Hex(), original.Hex())
	}
}

func TestParseHex_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too short", "abcd"},
		{"too long", "aabbccddaabbccddaabbccddaabbccddaa"},
		{"invalid chars", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHex(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHash_IsZero(t *testing.T) {
	var h Hash
	if !h.IsZero() {
		t.Fatal("default Hash should be zero")
	}

	h2 := HashFromRawOptions([]byte(`{"type":"ss"}`))
	if h2.IsZero() {
		t.Fatal("computed Hash should not be zero")
	}
}
