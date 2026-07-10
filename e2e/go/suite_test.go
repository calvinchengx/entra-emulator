// Real-SDK e2e suite against a running emulator (started by e2e/run.sh).
// Tests both MSAL Go and the azure-identity layer most Go services use.
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	spaID        = "cccccccc-0000-0000-0000-000000000001"
	daemonID     = "cccccccc-0000-0000-0000-000000000002"
	daemonSecret = "daemon-app-secret"
	aliceID      = "aaaaaaaa-0000-0000-0000-000000000001"
)

func env(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set — run via e2e/run.sh", key)
	}
	return v
}

// httpClient trusts the emulator's self-signed cert.
func httpClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(env(t, "EMU_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
}

func decodeJWT(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestMSALGoClientCredentials(t *testing.T) {
	origin, tenant := env(t, "EMU_ORIGIN"), env(t, "EMU_TENANT")
	cred, err := confidential.NewCredFromSecret(daemonSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := confidential.New(origin+"/"+tenant, daemonID, cred,
		confidential.WithHTTPClient(httpClient(t)),
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AcquireTokenByCredential(context.Background(),
		[]string{"api://" + daemonID + "/.default"})
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJWT(t, result.AccessToken)
	if claims["aud"] != "api://"+daemonID || claims["sub"] != daemonID {
		t.Fatalf("bad app-only claims: %v", claims)
	}
	roles, _ := json.Marshal(claims["roles"])
	if !strings.Contains(string(roles), "Tasks.Read.All") {
		t.Fatalf("missing auto-granted role: %s", roles)
	}
}

func TestMSALGoDeviceCode(t *testing.T) {
	origin, tenant := env(t, "EMU_ORIGIN"), env(t, "EMU_TENANT")
	hc := httpClient(t)
	client, err := public.New(spaID,
		public.WithAuthority(origin+"/"+tenant),
		public.WithHTTPClient(hc),
		public.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dc, err := client.AcquireTokenByDeviceCode(ctx, []string{"openid", "profile", "offline_access"})
	if err != nil {
		t.Fatal(err)
	}

	// Approve concurrently: lookup -> sign in as alice -> approve.
	approveErr := make(chan error, 1)
	go func() {
		approveErr <- approveDeviceCode(hc, origin, tenant, dc.Result.UserCode)
	}()

	result, err := dc.AuthenticationResult(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-approveErr; err != nil {
		t.Fatal(err)
	}
	claims := decodeJWT(t, result.AccessToken)
	if claims["oid"] != aliceID {
		t.Fatalf("expected approving user alice, got %v", claims["oid"])
	}
	if result.Account.PreferredUsername != "alice@entralocal.dev" {
		t.Fatalf("account identity: %+v", result.Account)
	}
}

var stateRe = regexp.MustCompile(`name="__el_state" value="([^"]+)"`)

func approveDeviceCode(hc *http.Client, origin, tenant, userCode string) error {
	verify := origin + "/" + tenant + "/oauth2/v2.0/devicecode/verify"
	post := func(form url.Values) (string, error) {
		resp, err := hc.PostForm(verify, form)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return string(raw), nil
	}
	page, err := post(url.Values{"__el_step": {"lookup"}, "user_code": {userCode}})
	if err != nil {
		return err
	}
	m := stateRe.FindStringSubmatch(page)
	if m == nil {
		return fmt.Errorf("no state on lookup page: %.300s", page)
	}
	page, err = post(url.Values{"__el_step": {"signin"}, "__el_state": {m[1]}, "__el_user": {aliceID}})
	if err != nil {
		return err
	}
	m = stateRe.FindStringSubmatch(page)
	if m == nil {
		return fmt.Errorf("no state on consent page: %.300s", page)
	}
	page, err = post(url.Values{"__el_step": {"decide"}, "__el_state": {m[1]}, "__el_decision": {"approve"}})
	if err != nil {
		return err
	}
	if !strings.Contains(page, "You're all set") {
		return fmt.Errorf("approve failed: %.300s", page)
	}
	return nil
}

// TestAzidentityClientSecret exercises the layer real Go services use.
func TestAzidentityClientSecret(t *testing.T) {
	origin, tenant := env(t, "EMU_ORIGIN"), env(t, "EMU_TENANT")
	cred, err := azidentity.NewClientSecretCredential(tenant, daemonID, daemonSecret,
		&azidentity.ClientSecretCredentialOptions{
			DisableInstanceDiscovery: true,
			ClientOptions: azcore.ClientOptions{
				Transport: httpClient(t),
				Cloud: cloud.Configuration{
					ActiveDirectoryAuthorityHost: origin,
					Services:                     map[cloud.ServiceName]cloud.ServiceConfiguration{},
				},
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJWT(t, tok.Token)
	if claims["aud"] != "https://graph.microsoft.com" || claims["ver"] != "2.0" {
		t.Fatalf("bad azidentity token claims: %v", claims)
	}

	// The token works against the emulator Graph.
	req, _ := http.NewRequest("GET", origin+"/graph/v1.0/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("graph with azidentity token: %d", resp.StatusCode)
	}
}
