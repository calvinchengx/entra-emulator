# MSAL.NET + Wilson

Microsoft.Identity.Client acquires a client-credentials token; **Wilson**
(`Microsoft.IdentityModel.Protocols.OpenIdConnect` +
`Microsoft.IdentityModel.JsonWebTokens`) validates it. That is the stack
ASP.NET Core JwtBearer uses against production Entra: discover the tenant,
pull JWKS, check `alg` / `kid` / issuer / audience / lifetime, reject a
tampered signature.

Runs inside CI `sdk-e2e` via `e2e/run.py dotnet`.
