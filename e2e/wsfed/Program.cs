// KPI-1: unmodified Microsoft.AspNetCore.Authentication.WsFederation completes
// metadata fetch, sign-in, and SignOut against a running emulator (via e2e/run.py).
// Sibling of e2e/saml, not an extension of e2e/dotnet (that job is MSAL.NET).
// Host and TLS knobs only versus Entra. Do not log raw wresult.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;

string origin = Environment.GetEnvironmentVariable("EMU_ORIGIN")
    ?? throw new InvalidOperationException("EMU_ORIGIN is required");
string tenant = Environment.GetEnvironmentVariable("EMU_TENANT")
    ?? throw new InvalidOperationException("EMU_TENANT is required");
string certPath = Environment.GetEnvironmentVariable("EMU_CERT")
    ?? throw new InvalidOperationException("EMU_CERT is required");

const string Wtrealm = "api://tasks-api";
const string ReplyPath = "/signin-wsfed";
const string SignOutPath = "/wsfed-signed-out";

int failures = 0;
void Check(string name, bool cond, string extra = "")
{
    Console.WriteLine(cond ? $"  ok  {name}" : $"  FAIL {name} {extra}");
    if (!cond) failures++;
}

var asm = typeof(WsFederationHandler).Assembly.GetName();
Console.WriteLine($"WsFederation {asm.Name} {asm.Version} against {origin}");

var emuCert = X509Certificate2.CreateFromPem(File.ReadAllText(certPath));
var backchannel = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
        errors == SslPolicyErrors.None
        || (cert is not null && cert.GetCertHashString() == emuCert.GetCertHashString()),
});

int port = FreePort();
string rpOrigin = $"http://127.0.0.1:{port}";
string wreply = rpOrigin + ReplyPath;
string signOutWreply = rpOrigin + SignOutPath;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = [],
    EnvironmentName = Environments.Development,
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port));
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
})
.AddCookie(cookie =>
{
    cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
})
.AddWsFederation(o =>
{
    o.MetadataAddress = $"{origin}/{tenant}/federationmetadata/2007-06/federationmetadata.xml";
    o.Wtrealm = Wtrealm;
    o.Wreply = wreply;
    o.CallbackPath = ReplyPath;
    o.SignOutWreply = signOutWreply;
    o.Backchannel = backchannel;
    // Loopback HTTP: SameAsRequest so the correlation cookie is stored and
    // sent. Entra-facing apps keep the package defaults (HTTPS / Secure).
    o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.CorrelationCookie.SameSite = SameSiteMode.Lax;
    o.Events = new WsFederationEvents
    {
        OnAuthenticationFailed = ctx =>
        {
            Console.Error.WriteLine(
                $"  FAIL middleware rejected token: {ctx.Exception?.GetType().Name}: {SafeText(ctx.Exception?.Message)}");
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            ctx.HandleResponse();
            return Task.CompletedTask;
        },
    };
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/secure", (ClaimsPrincipal user) =>
{
    if (user.Identity?.IsAuthenticated != true)
        return Results.Challenge();
    string name = user.FindFirstValue(ClaimTypes.Name)
        ?? user.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
        ?? user.Identity.Name
        ?? "unknown";
    return Results.Text($"authenticated:{name}");
});
app.MapGet("/signout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(WsFederationDefaults.AuthenticationScheme);
});
app.MapGet(SignOutPath, () => Results.Text("signed-out"));

await app.StartAsync();
try
{
    var rpCookies = new CookieContainer();
    using var rpHttp = new HttpClient(new HttpClientHandler
    {
        CookieContainer = rpCookies,
        AllowAutoRedirect = false,
    })
    { BaseAddress = new Uri(rpOrigin) };

    var emuCookies = new CookieContainer();
    using var emuHttp = new HttpClient(new HttpClientHandler
    {
        CookieContainer = emuCookies,
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            errors == SslPolicyErrors.None
            || (cert is not null && cert.GetCertHashString() == emuCert.GetCertHashString()),
    });

    var registered = await emuHttp.PostAsJsonAsync($"{origin}/admin/api/apps", new
    {
        displayName = "Tasks API",
        appIdUri = Wtrealm,
        redirectUris = new[]
        {
            new { uri = wreply, type = "wsfed-reply" },
            new { uri = signOutWreply, type = "wsfed-reply" },
        },
    });
    Check("Tasks API registered with two wsfed-reply URIs",
        registered.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK,
        $"{(int)registered.StatusCode} {SafeText(await registered.Content.ReadAsStringAsync())}");

    var challenge = await rpHttp.GetAsync("/secure");
    string? location = challenge.Headers.Location?.ToString();
    Check("middleware fetched metadata and challenged /wsfed",
        challenge.StatusCode == HttpStatusCode.Redirect
        && location is not null
        && location.Contains($"/{tenant}/wsfed", StringComparison.Ordinal)
        && location.Contains("wa=wsignin1.0", StringComparison.Ordinal)
        && location.Contains("wtrealm=", StringComparison.Ordinal),
        $"{(int)challenge.StatusCode} {location}");
    if (location is null || failures > 0)
    {
        Console.WriteLine(failures == 0 ? "PASS" : $"FAIL ({failures})");
        return failures == 0 ? 0 : 1;
    }

    var picker = await emuHttp.GetAsync(location);
    string pickerHtml = await picker.Content.ReadAsStringAsync();
    Check("emulator shows Pick an account",
        picker.StatusCode == HttpStatusCode.OK
        && pickerHtml.Contains("LOCAL EMULATOR", StringComparison.Ordinal)
        && pickerHtml.Contains("Pick an account", StringComparison.Ordinal),
        $"{(int)picker.StatusCode} {SafeText(pickerHtml)}");

    string? state = FormValue(pickerHtml, "__ee_state");
    string? user = UserIdFor(pickerHtml, "alice@entraemulator.dev");
    Check("picker carries signed state and an account",
        !string.IsNullOrEmpty(state) && !string.IsNullOrEmpty(user));
    if (state is null || user is null)
    {
        Console.WriteLine($"FAIL ({failures})");
        return 1;
    }

    var signedIn = await emuHttp.PostAsync(
        $"{origin}/{tenant}/wsfed",
        new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__ee_state"] = state,
            ["__ee_user"] = user,
        }));
    string autoPost = await signedIn.Content.ReadAsStringAsync();
    string? wresult = FormValue(autoPost, "wresult");
    string? wa = FormValue(autoPost, "wa");
    string? wctx = FormValue(autoPost, "wctx");
    Check("emulator returned wresult auto-POST",
        signedIn.StatusCode == HttpStatusCode.OK
        && wa == "wsignin1.0"
        && !string.IsNullOrEmpty(wresult),
        $"{(int)signedIn.StatusCode} {SafeText(autoPost)}");
    if (string.IsNullOrEmpty(wresult))
    {
        Console.WriteLine($"FAIL ({failures})");
        return 1;
    }
    Console.WriteLine("  ok  wresult accepted for callback (body not logged)");

    var fields = new Dictionary<string, string> { ["wa"] = wa ?? "wsignin1.0", ["wresult"] = wresult };
    if (!string.IsNullOrEmpty(wctx))
        fields["wctx"] = wctx;

    var callback = await rpHttp.PostAsync(ReplyPath, new FormUrlEncodedContent(fields));
    Check("unmodified middleware accepted the token",
        callback.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK,
        $"{(int)callback.StatusCode} {SafeText(await callback.Content.ReadAsStringAsync())}");

    var session = await rpHttp.GetAsync("/secure");
    string body = await session.Content.ReadAsStringAsync();
    Check("Priya has an authenticated session at the Tasks API",
        session.IsSuccessStatusCode && body.StartsWith("authenticated:", StringComparison.Ordinal),
        $"{(int)session.StatusCode} {SafeText(body)}");
    Check("session subject is the account that signed in",
        body.Contains("alice@entraemulator.dev", StringComparison.Ordinal),
        SafeText(body));

    // KPI-1 SignOut: unmodified library SignOut after v0.8.0 sign-in.
    // SignOutWreply must be distinct from CallbackPath (spike return-URL trap).
    var signOut = await rpHttp.GetAsync("/signout");
    string? signOutLoc = signOut.Headers.Location?.ToString();
    Check("unmodified SignOut redirects wa=wsignout1.0 with distinct SignOutWreply",
        signOut.StatusCode == HttpStatusCode.Redirect
        && signOutLoc is not null
        && signOutLoc.Contains($"/{tenant}/wsfed", StringComparison.Ordinal)
        && signOutLoc.Contains("wa=wsignout1.0", StringComparison.Ordinal)
        && signOutLoc.Contains("wtrealm=", StringComparison.Ordinal)
        && signOutLoc.Contains("wsfed-signed-out", StringComparison.Ordinal)
        && !signOutLoc.Contains("signin-wsfed", StringComparison.Ordinal),
        $"{(int)signOut.StatusCode} {signOutLoc}");
    if (signOutLoc is null || failures > 0)
    {
        Console.WriteLine($"FAIL ({failures})");
        return 1;
    }

    var stsSignOut = await emuHttp.GetAsync(signOutLoc);
    string? signedOutLoc = stsSignOut.Headers.Location?.ToString();
    Check("emulator 302s SignOut to registered SignOutWreply",
        stsSignOut.StatusCode == HttpStatusCode.Redirect
        && signedOutLoc is not null
        && signedOutLoc.Contains("wsfed-signed-out", StringComparison.Ordinal)
        && !signedOutLoc.Contains("signin-wsfed", StringComparison.Ordinal),
        $"{(int)stsSignOut.StatusCode} {signedOutLoc} {SafeText(await stsSignOut.Content.ReadAsStringAsync())}");
    if (signedOutLoc is null)
    {
        Console.WriteLine($"FAIL ({failures})");
        return 1;
    }

    var signedOutPage = await rpHttp.GetAsync(new Uri(signedOutLoc).PathAndQuery);
    string signedOutBody = await signedOutPage.Content.ReadAsStringAsync();
    Check("Tasks API shows signed-out page",
        signedOutPage.IsSuccessStatusCode
        && signedOutBody.Contains("signed-out", StringComparison.OrdinalIgnoreCase),
        $"{(int)signedOutPage.StatusCode} {SafeText(signedOutBody)}");

    var afterSignOut = await rpHttp.GetAsync("/secure");
    string? afterLoc = afterSignOut.Headers.Location?.ToString();
    Check("GET /secure is unauthenticated after SignOut",
        afterSignOut.StatusCode == HttpStatusCode.Redirect
        && afterLoc is not null
        && afterLoc.Contains("wa=wsignin1.0", StringComparison.Ordinal),
        $"{(int)afterSignOut.StatusCode} {afterLoc} {SafeText(await afterSignOut.Content.ReadAsStringAsync())}");
    if (afterLoc is null || failures > 0)
    {
        Console.WriteLine($"FAIL ({failures})");
        return 1;
    }

    var nextPicker = await emuHttp.GetAsync(afterLoc);
    string nextHtml = await nextPicker.Content.ReadAsStringAsync();
    Check("next challenge shows Pick an account",
        nextPicker.StatusCode == HttpStatusCode.OK
        && nextHtml.Contains("Pick an account", StringComparison.Ordinal)
        && nextHtml.Contains("LOCAL EMULATOR", StringComparison.Ordinal)
        && !nextHtml.Contains("wresult", StringComparison.Ordinal),
        $"{(int)nextPicker.StatusCode} {SafeText(nextHtml)}");
}
finally
{
    await app.StopAsync();
}

Console.WriteLine(failures == 0 ? "PASS" : $"FAIL ({failures})");
return failures == 0 ? 0 : 1;

static int FreePort()
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    int p = ((IPEndPoint)listener.LocalEndpoint).Port;
    listener.Stop();
    return p;
}

static string? FormValue(string html, string name)
{
    var m = Regex.Match(html, $@"name=""{Regex.Escape(name)}"" value=""([^""]*)""");
    return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value) : null;
}

static string? UserIdFor(string html, string upn)
{
    foreach (Match li in Regex.Matches(html, @"<li>([\s\S]*?)</li>"))
    {
        if (!li.Groups[1].Value.Contains(upn, StringComparison.OrdinalIgnoreCase))
            continue;
        return FormValue(li.Groups[1].Value, "__ee_user");
    }
    return FormValue(html, "__ee_user");
}

static string SafeText(string? s)
{
    if (string.IsNullOrEmpty(s))
        return "";
    string redacted = Regex.Replace(s, @"name=""wresult"" value=""[^""]*""",
        @"name=""wresult"" value=""[redacted]""", RegexOptions.IgnoreCase);
    redacted = Regex.Replace(redacted, @"<t:RequestedSecurityToken>[\s\S]*?</t:RequestedSecurityToken>",
        "<t:RequestedSecurityToken>[redacted]</t:RequestedSecurityToken>", RegexOptions.IgnoreCase);
    return redacted.Length <= 400 ? redacted : redacted[..400];
}
