// Minimal MSAL Go sample: acquire an app-only (client-credentials) token from
// the emulator and call the emulated Microsoft Graph with it.
//
//	1. Start the emulator:  ORIGIN_MODE=compat ./entra-emulator
//	2. Run this sample:     cd samples/msal-go && go run .
//
// Every value defaults to a seeded dev constant; override via env if needed.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	origin := env("EMU_ORIGIN", "https://localhost:8443")
	tenant := env("EMU_TENANT", "11111111-1111-1111-1111-111111111111")
	clientID := env("EMU_CLIENT_ID", "cccccccc-0000-0000-0000-000000000002")
	secret := env("EMU_CLIENT_SECRET", "daemon-app-secret")
	certPath := env("EMU_CERT", "../../data/tls/cert.pem")

	// Trust the emulator's self-signed cert. MSAL Go requires HTTPS.
	pem, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("read cert %s: %v (run `entra-emulator cert-path`)", certPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("cert file is not valid PEM")
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	cred, err := confidential.NewCredFromSecret(secret)
	if err != nil {
		log.Fatal(err)
	}
	client, err := confidential.New(origin+"/"+tenant, clientID, cred,
		confidential.WithHTTPClient(hc),
		// Emulator isn't a real cloud; skip instance discovery against AAD.
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.AcquireTokenByCredential(context.Background(),
		[]string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Fatal(err)
	}
	claims := decodeJWT(res.AccessToken)
	exp, _ := claims["exp"].(float64) // JSON numbers decode to float64
	fmt.Printf("✓ token acquired — aud=%v appid=%v exp=%d\n", claims["aud"], claims["appid"], int64(exp))

	// Call the emulated Graph with the token.
	req, _ := http.NewRequest("GET", origin+"/graph/v1.0/users", nil)
	req.Header.Set("Authorization", "Bearer "+res.AccessToken)
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var page struct {
		Value []struct {
			DisplayName       string `json:"displayName"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"value"`
	}
	_ = json.Unmarshal(body, &page)
	fmt.Printf("✓ GET /graph/v1.0/users → %d, %d users:\n", resp.StatusCode, len(page.Value))
	for _, u := range page.Value {
		fmt.Printf("    - %s <%s>\n", u.DisplayName, u.UserPrincipalName)
	}
}

func decodeJWT(jwt string) map[string]any {
	parts := splitDots(jwt)
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	return claims
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
