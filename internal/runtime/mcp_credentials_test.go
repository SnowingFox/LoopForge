package runtime

import (
	"strings"
	"testing"

	"agentflow/internal/domain"
)

func credentialServer(name, kind string, headers map[string]string) domain.MCPServerDefinition {
	return domain.MCPServerDefinition{
		ID: "srv-" + name, Name: name, Transport: "http", URL: "https://" + name + ".example",
		AuthType: MCPAuthCredential, CredentialKind: kind, Headers: headers,
	}
}

func TestBindCredentialMCPHeadersInjectsBearer(t *testing.T) {
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{
		credentialServer("gateway", "corp-gateway", nil),
	}}
	out, err := BindCredentialMCPHeaders(assets, map[string]string{"corp-gateway": "tok-1"})
	if err != nil {
		t.Fatalf("BindCredentialMCPHeaders: %v", err)
	}
	if got := out.MCPServers[0].Headers["Authorization"]; got != "Bearer tok-1" {
		t.Fatalf("Authorization: got %q, want %q", got, "Bearer tok-1")
	}
	// The stored asset must not be mutated.
	if _, ok := assets.MCPServers[0].Headers["Authorization"]; ok {
		t.Fatal("stored MCP asset was mutated")
	}
}

func TestBindCredentialMCPHeadersReplacesStoredAuthorization(t *testing.T) {
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{
		credentialServer("gateway", "corp-gateway", map[string]string{"authorization": "stale", "X-Keep": "v"}),
	}}
	out, err := BindCredentialMCPHeaders(assets, map[string]string{"corp-gateway": "tok-2"})
	if err != nil {
		t.Fatalf("BindCredentialMCPHeaders: %v", err)
	}
	srv := out.MCPServers[0]
	if got := srv.Headers["Authorization"]; got != "Bearer tok-2" {
		t.Fatalf("Authorization: got %q, want %q", got, "Bearer tok-2")
	}
	for key := range srv.Headers {
		if strings.EqualFold(key, "authorization") && key != "Authorization" {
			t.Fatalf("stale Authorization header %q survived", key)
		}
	}
	if srv.Headers["X-Keep"] != "v" {
		t.Fatal("unrelated headers must survive")
	}
}

func TestBindCredentialMCPHeadersMissingCredentialFails(t *testing.T) {
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{
		credentialServer("gateway", "corp-gateway", nil),
	}}
	if _, err := BindCredentialMCPHeaders(assets, nil); err == nil {
		t.Fatal("missing credential must fail")
	} else if !strings.Contains(err.Error(), "corp-gateway") {
		t.Fatalf("error must name the server and credential: %v", err)
	}
}

func TestBindCredentialMCPHeadersMissingKindFails(t *testing.T) {
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{
		credentialServer("gateway", "  ", nil),
	}}
	if _, err := BindCredentialMCPHeaders(assets, map[string]string{"x": "y"}); err == nil {
		t.Fatal("empty credentialKind must fail")
	}
}

func TestBindCredentialMCPHeadersIgnoresOtherServers(t *testing.T) {
	plain := domain.MCPServerDefinition{ID: "p", Name: "plain", Transport: "http", URL: "https://plain.example"}
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{plain}}
	out, err := BindCredentialMCPHeaders(assets, nil)
	if err != nil {
		t.Fatalf("BindCredentialMCPHeaders: %v", err)
	}
	if out.MCPServers[0].Headers != nil {
		t.Fatal("non-credential servers must stay untouched")
	}
}

func TestPrepareMCPServersBindsCredentialAuth(t *testing.T) {
	assets := domain.AgentAssetBundle{MCPServers: []domain.MCPServerDefinition{
		credentialServer("gateway", "corp-gateway", nil),
	}}
	out, warnings, err := PrepareMCPServers(assets, MCPTarget{ExtraCredentials: map[string]string{"corp-gateway": "tok-3"}})
	if err != nil {
		t.Fatalf("PrepareMCPServers: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if got := out.MCPServers[0].Headers["Authorization"]; got != "Bearer tok-3" {
		t.Fatalf("Authorization: got %q, want %q", got, "Bearer tok-3")
	}
}
