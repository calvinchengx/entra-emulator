package identity

import "testing"

func TestAzureAud(t *testing.T) {
	cases := map[string]string{
		"https://vault.azure.net":            "https://vault.azure.net",
		"https://vault.azure.net/":           "https://vault.azure.net/",
		"https://storage.azure.com":          "https://storage.azure.com",
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
