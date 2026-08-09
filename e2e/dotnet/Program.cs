// Real-MSAL.NET e2e suite (Microsoft.Identity.Client) against a running
// emulator (via e2e/run.sh). Client credentials → app-only token, then real
// signature validation through Microsoft.IdentityModel — the same stack
// ASP.NET Core's JwtBearer middleware uses against production Entra.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
using System.Net.Http.Json;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

string origin = Environment.GetEnvironmentVariable("EMU_ORIGIN")!;
string tenant = Environment.GetEnvironmentVariable("EMU_TENANT")!;
string authority = $"{origin}/{tenant}";
const string DaemonId = "00d88624-f0d7-46f6-a641-6232c2608928";
const string DaemonSecret = "daemon-app-secret";
string audience = $"api://{DaemonId}";
string metadata = $"{authority}/v2.0/.well-known/openid-configuration";

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
var http = new HttpClient(handler);
var factory = new SingleClientFactory(http);

IConfidentialClientApplication NewApp() => ConfidentialClientApplicationBuilder
    .Create(DaemonId)
    .WithClientSecret(DaemonSecret)
    .WithAuthority(new Uri(authority), validateAuthority: false)
    .WithInstanceDiscovery(false)
    .WithHttpClientFactory(factory)
    .Build();

// --- Client credentials ---
// AAD-style authority + instance discovery off, exactly like the other SDKs:
// MSAL treats the emulator as a normal tenant and never calls login.microsoftonline.com.
var cca = NewApp();

var result = await cca.AcquireTokenForClient(new[] { $"{audience}/.default" }).ExecuteAsync();
Check("client_credentials: token acquired", !string.IsNullOrEmpty(result.AccessToken));

string payload = DecodePayload(result.AccessToken);
Check("client_credentials: aud + roles",
    payload.Contains($"\"aud\":\"{audience}\"") && payload.Contains("Tasks.Read.All"), payload);
Check("client_credentials: no scp/oid", !payload.Contains("\"scp\"") && !payload.Contains("\"oid\""), payload);

// Cached second call returns from MSAL's in-memory cache (no network).
var again = await cca.AcquireTokenForClient(new[] { $"{audience}/.default" }).ExecuteAsync();
Check("client_credentials: cache hit", again.AuthenticationResultMetadata.TokenSource == TokenSource.Cache);

// --- Real signature validation (witnesses `token-signing-algorithm`) ---
// Microsoft.IdentityModel discovers the tenant's OIDC metadata, pulls JWKS and
// verifies the signature itself. Nothing here trusts our own decoder: a bad
// signature, a wrong issuer or an unadvertised alg all fail this block.
var config = await FetchConfig();
Check("discovery: RS256 advertised", config.IdTokenSigningAlgValuesSupported.Contains("RS256"),
    string.Join(",", config.IdTokenSigningAlgValuesSupported));
Check("discovery: issuer matches authority", config.Issuer == $"{authority}/v2.0", config.Issuer);

var firstToken = result.AccessToken;
var firstResult = await Validate(firstToken, config);
Check("validation: MSAL.NET-issued token verifies against JWKS", firstResult.IsValid,
    firstResult.Exception?.Message ?? "");

var firstJwt = new JsonWebToken(firstToken);
Check("validation: alg is RS256", firstJwt.Alg == "RS256", firstJwt.Alg);
Check("validation: kid present and published",
    !string.IsNullOrEmpty(firstJwt.Kid) && config.SigningKeys.Any(k => k.KeyId == firstJwt.Kid), firstJwt.Kid);

// A tampered payload must fail: proves the check above is real, not incidental.
var tampered = Tamper(firstToken);
var tamperedResult = await Validate(tampered, config);
Check("validation: tampered token rejected for bad signature",
    !tamperedResult.IsValid && tamperedResult.Exception is SecurityTokenInvalidSignatureException,
    tamperedResult.Exception?.GetType().Name ?? "no exception");

// --- Signing-key rotation (witnesses `signing-key-rotation`) ---
// Rotate with a grace window, then assert both halves of the claim: new tokens
// are signed by the new key, and tokens already in flight keep validating
// because the retired key is still published until it expires.
var rotate = await http.PostAsJsonAsync($"{origin}/admin/api/signing-keys/rotate",
    new { graceSeconds = 3600 });
Check("rotation: admin rotate accepted", rotate.IsSuccessStatusCode, $"{(int)rotate.StatusCode}");

var rotated = await FetchConfig();
Check("rotation: JWKS publishes retired + active", rotated.SigningKeys.Count >= 2,
    $"{rotated.SigningKeys.Count} key(s)");

// Fresh app instance so MSAL's cache cannot hand back the pre-rotation token.
var afterApp = NewApp();
var after = await afterApp.AcquireTokenForClient(new[] { $"{audience}/.default" }).ExecuteAsync();
var afterJwt = new JsonWebToken(after.AccessToken);
Check("rotation: new token signed by the new key", afterJwt.Kid != firstJwt.Kid,
    $"{afterJwt.Kid} vs {firstJwt.Kid}");

var afterResult = await Validate(after.AccessToken, rotated);
Check("rotation: post-rotation token verifies", afterResult.IsValid, afterResult.Exception?.Message ?? "");

var inFlight = await Validate(firstToken, rotated);
Check("rotation: pre-rotation token still verifies (grace window)", inFlight.IsValid,
    inFlight.Exception?.Message ?? "");

Console.WriteLine(failures == 0 ? "PASS" : $"FAIL ({failures})");
return failures == 0 ? 0 : 1;

// Fetch OIDC metadata + JWKS fresh. A new manager each call keeps the assertion
// about the emulator's JWKS rather than about ConfigurationManager's cache
// timers, which would make the rotation check timing-dependent.
async Task<OpenIdConnectConfiguration> FetchConfig()
{
    var mgr = new ConfigurationManager<OpenIdConnectConfiguration>(
        metadata,
        new OpenIdConnectConfigurationRetriever(),
        new HttpDocumentRetriever(http) { RequireHttps = true });
    return await mgr.GetConfigurationAsync(CancellationToken.None);
}

async Task<TokenValidationResult> Validate(string token, OpenIdConnectConfiguration cfg) =>
    await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
    {
        ValidIssuer = cfg.Issuer,
        ValidAudience = audience,
        IssuerSigningKeys = cfg.SigningKeys,
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
    });

// Flip one byte of the SIGNATURE, leaving header and payload intact. Tampering
// the payload instead would fail as malformed JSON (ArgumentException) before
// any crypto ran, which would prove nothing about signature checking.
static string Tamper(string jwt)
{
    string[] parts = jwt.Split('.');
    char[] s = parts[2].ToCharArray();
    s[0] = s[0] == 'A' ? 'B' : 'A';
    return $"{parts[0]}.{parts[1]}.{new string(s)}";
}

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
