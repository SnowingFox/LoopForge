package runtime

import (
	"fmt"
	"strings"

	"agentflow/internal/domain"
)

func cloneHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// MCPAuthCredential is the MCPServerDefinition.AuthType value that binds a
// platform-managed credential as the server's Authorization Bearer header.
// The credential itself is named by MCPServerDefinition.CredentialKind and
// resolved from RunCredentials.Extra per run, so a stored asset never holds
// the secret.
const MCPAuthCredential = "credential"

// BindCredentialMCPHeaders binds the responsible user's saved credential
// (named by CredentialKind) into HTTP MCP servers that opt in with
// AuthType "credential". Stored MCP assets are never mutated: the bundle is
// copied per task, and any Authorization header stored on the asset is
// replaced so the credential is the only authority.
func BindCredentialMCPHeaders(assets domain.AgentAssetBundle, extra map[string]string) (domain.AgentAssetBundle, error) {
	out := assets
	out.MCPServers = append([]domain.MCPServerDefinition(nil), assets.MCPServers...)
	for i := range out.MCPServers {
		server := &out.MCPServers[i]
		if !strings.EqualFold(strings.TrimSpace(server.AuthType), MCPAuthCredential) {
			continue
		}
		kind := strings.TrimSpace(server.CredentialKind)
		if kind == "" {
			return out, fmt.Errorf("MCP %s declares credential authentication without a credentialKind", server.Name)
		}
		token := strings.TrimSpace(extra[kind])
		if token == "" {
			return out, fmt.Errorf("MCP %s requires the saved credential %q; configure it in personal settings", server.Name, kind)
		}
		server.Headers = cloneHeaders(server.Headers)
		for key := range server.Headers {
			if strings.EqualFold(strings.TrimSpace(key), "authorization") {
				delete(server.Headers, key)
			}
		}
		server.Headers["Authorization"] = "Bearer " + token
	}
	return out, nil
}

// RequiresMCPCredential reports whether any server needs a saved credential.
func RequiresMCPCredential(assets domain.AgentAssetBundle) bool {
	for _, server := range assets.MCPServers {
		if strings.EqualFold(strings.TrimSpace(server.AuthType), MCPAuthCredential) {
			return true
		}
	}
	return false
}
