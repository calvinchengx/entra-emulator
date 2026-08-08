package identity

import "strings"

// Well-known first-party Azure resources. Like the Fabric carve-out, these
// let client-credentials and MSI callers acquire a correct-audience token for
// a recognized Azure service without registering a resource app first — the
// common case for tools (azsecrets, azstorage, the ARM SDK) pointed at the
// emulator. The audience echoes the canonical resource URI Azure uses.
var knownAzureResources = map[string]string{
	"https://vault.azure.net":             "https://vault.azure.net",
	"https://storage.azure.com":           "https://storage.azure.com",
	"https://management.azure.com":        "https://management.azure.com",
	"https://management.core.windows.net": "https://management.azure.com",
	"https://cognitiveservices.azure.com": "https://cognitiveservices.azure.com",
}

// azureAud maps a recognized Azure resource identifier to the audience used
// in issued tokens. The trailing slash is accepted and preserved, matching
// how Azure keeps the caller's resource form. Returns "" when unrecognized.
func azureAud(resource string) string {
	if aud, ok := knownAzureResources[resource]; ok {
		return aud
	}
	if trimmed := strings.TrimSuffix(resource, "/"); trimmed != resource {
		if aud, ok := knownAzureResources[trimmed]; ok {
			return aud + "/"
		}
	}
	return ""
}

// azureDelegatedResource recognizes a delegated scope aimed at a well-known
// Azure resource ("https://vault.azure.net/.default",
// "https://storage.azure.com/user_impersonation") and returns the resource
// part; "" when the scope is not one of these.
func azureDelegatedResource(scope string) string {
	idx := strings.LastIndex(scope, "/")
	if idx <= 0 {
		return ""
	}
	resource := scope[:idx]
	if azureAud(resource) != "" {
		return resource
	}
	return ""
}
