package identity

import "testing"

func TestAzureAud(t *testing.T) {
	cases := map[string]string{
		"https://vault.azure.net":             "https://vault.azure.net",
		"https://vault.azure.net/":            "https://vault.azure.net/",
		"https://storage.azure.com":           "https://storage.azure.com",
		"https://management.azure.com":        "https://management.azure.com",
		"https://management.core.windows.net": "https://management.azure.com",
		"https://graph.microsoft.com":         "", // Graph resolves elsewhere
		"https://unknown.example.com":         "",
	}
	for res, want := range cases {
		if got := azureAud(res); got != want {
			t.Errorf("azureAud(%q) = %q; want %q", res, got, want)
		}
	}
}

func TestAzureDelegatedResource(t *testing.T) {
	cases := map[string]string{
		"https://vault.azure.net/.default":             "https://vault.azure.net",
		"https://vault.azure.net/user_impersonation":   "https://vault.azure.net",
		"https://management.azure.com/.default":        "https://management.azure.com",
		"https://management.core.windows.net/.default": "https://management.core.windows.net",
		"https://storage.azure.com/user_impersonation": "https://storage.azure.com",
		// Not a well-known Azure resource, or not resource-qualified.
		"https://graph.microsoft.com/User.Read": "",
		"api://some-app/scope":                  "",
		"User.Read":                             "",
		"/leading-slash":                        "",
		"":                                      "",
	}
	for scope, want := range cases {
		if got := azureDelegatedResource(scope); got != want {
			t.Errorf("azureDelegatedResource(%q) = %q; want %q", scope, got, want)
		}
	}
}
