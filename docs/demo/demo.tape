# Regenerate the README demo GIF:  vhs docs/demo/demo.tape   (run from the repo root)
# Requires: vhs, ttyd, ffmpeg, go, curl, jq.
Output docs/demo/demo.gif

Require go
Require curl
Require jq

Set Shell bash
Set FontSize 19
Set Width 1240
Set Height 680
Set Padding 22
Set Margin 16
Set MarginFill "#1e1e2e"
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms

# --- setup (not shown): build + start the emulator, env vars, jwt decoder on PATH ---
Hide
Type "go build -o /tmp/ee-demo ./cmd/entra-emulator" Enter
Sleep 6s
Type "rm -f /tmp/ee-demo.db; TLS_ENABLED=false PORT=8099 ORIGIN_MODE=compat DB_PATH=/tmp/ee-demo.db SEED_ON_START=true /tmp/ee-demo >/tmp/ee-demo.log 2>&1 &" Enter
Type "until curl -sf localhost:8099/health >/dev/null 2>&1; do sleep 0.3; done" Enter
Sleep 2s
Type "export PATH=$PWD/docs/demo:$PATH" Enter
Type "PS1='$ '" Enter
Type "I=http://localhost:8099/6f89cf12-978b-4d23-ac18-9ef0c127cf87/v2.0" Enter
Type "T=http://localhost:8099/6f89cf12-978b-4d23-ac18-9ef0c127cf87/oauth2/v2.0/token" Enter
Type "C=00d88624-f0d7-46f6-a641-6232c2608928" Enter
Type "S=daemon-app-secret" Enter
Type "R=api://00d88624-f0d7-46f6-a641-6232c2608928/.default" Enter
Type "clear" Enter
Show

Sleep 600ms
Type "# Entra Emulator - Microsoft Entra ID (Azure AD), local, one Go binary" Enter
Sleep 800ms

Type "# 1. OIDC discovery - exactly what MSAL fetches" Enter
Sleep 500ms
Type "curl -s $I/.well-known/openid-configuration | jq '{issuer, token_endpoint, jwks_uri}'" Enter
Sleep 1700ms

Type "# 2. App-only token - the client-credentials flow, unchanged" Enter
Sleep 500ms
Type "TOK=$(curl -s -X POST $T -d grant_type=client_credentials -d client_id=$C -d client_secret=$S -d scope=$R | jq -r .access_token)" Enter
Sleep 1000ms
Type "echo ${TOK:0:40}..." Enter
Sleep 1000ms

Type "# 3. A real RS256 JWT with Entra v2.0 claims" Enter
Sleep 500ms
Type "echo $TOK | jwt | jq '{aud, tid, appid, roles, iss}'" Enter
Sleep 2200ms

Type "# No cloud tenant. Deterministic seed. MSAL just works." Enter
Sleep 1700ms

# --- teardown (not shown) ---
Hide
Type "kill %1 2>/dev/null" Enter
Show
