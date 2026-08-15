package identity

import "testing"

func TestDatabricksAud(t *testing.T) {
	if got := databricksAud(databricksFirstPartyAppID); got != databricksFirstPartyAppID {
		t.Fatalf("databricksAud(app id) = %q", got)
	}
	if got := databricksAud("https://vault.azure.net"); got != "" {
		t.Fatalf("databricksAud(vault) = %q", got)
	}
}
