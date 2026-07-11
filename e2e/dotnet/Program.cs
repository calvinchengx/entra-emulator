// Real-MSAL.NET e2e suite (Microsoft.Identity.Client) against a running
// emulator (via e2e/run.sh). Client credentials → app-only token.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
using Microsoft.Identity.Client;

string origin = Environment.GetEnvironmentVariable("EMU_ORIGIN")!;
string tenant = Environment.GetEnvironmentVariable("EMU_TENANT")!;
string authority = $"{origin}/{tenant}";
const string DaemonId = "cccccccc-0000-0000-0000-000000000002";
const string DaemonSecret = "daemon-app-secret";

int failures = 0;
void Check(string name, bool cond, string extra = "")
{
    Console.WriteLine(cond ? $"  ok  {name}" : $"  FAIL {name} {extra}");
    if (!cond) failures++;
}

Console.WriteLine($"MSAL.NET flows against {authority}");

// Trust the emulator's self-signed cert (dev only).
var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
};
var factory = new SingleClientFactory(new HttpClient(handler));

// --- Client credentials ---
// AAD-style authority + instance discovery off, exactly like the other SDKs:
// MSAL treats the emulator as a normal tenant and never calls login.microsoftonline.com.
var cca = ConfidentialClientApplicationBuilder
    .Create(DaemonId)
    .WithClientSecret(DaemonSecret)
    .WithAuthority(new Uri(authority), validateAuthority: false)
    .WithInstanceDiscovery(false)
    .WithHttpClientFactory(factory)
    .Build();

var result = await cca.AcquireTokenForClient(new[] { $"api://{DaemonId}/.default" }).ExecuteAsync();
Check("client_credentials: token acquired", !string.IsNullOrEmpty(result.AccessToken));

string payload = DecodePayload(result.AccessToken);
Check("client_credentials: aud + roles",
    payload.Contains($"\"aud\":\"api://{DaemonId}\"") && payload.Contains("Tasks.Read.All"), payload);
Check("client_credentials: no scp/oid", !payload.Contains("\"scp\"") && !payload.Contains("\"oid\""), payload);

// Cached second call returns from MSAL's in-memory cache (no network).
var again = await cca.AcquireTokenForClient(new[] { $"api://{DaemonId}/.default" }).ExecuteAsync();
Check("client_credentials: cache hit", again.AuthenticationResultMetadata.TokenSource == TokenSource.Cache);

Console.WriteLine(failures == 0 ? "PASS" : $"FAIL ({failures})");
return failures == 0 ? 0 : 1;

// base64url-decode the JWT payload segment to raw JSON.
static string DecodePayload(string jwt)
{
    string p = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
    p = (p.Length % 4) switch { 2 => p + "==", 3 => p + "=", _ => p };
    return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(p));
}

// Hands MSAL a single cert-trusting HttpClient.
class SingleClientFactory : IMsalHttpClientFactory
{
    private readonly HttpClient _client;
    public SingleClientFactory(HttpClient client) => _client = client;
    public HttpClient GetHttpClient() => _client;
}
