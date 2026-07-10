package identity

import (
	"fmt"
	"html"
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Server-rendered sign-in chrome. Deliberately small: a centered card, the
// amber LOCAL EMULATOR badge, and stable field names tests can target.

const pageShell = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — Entra Emulator</title>
<style>
body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;background:#faf9f8;color:#201f1e;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border-radius:8px;box-shadow:0 1.6px 3.6px rgba(0,0,0,.13),0 .3px .9px rgba(0,0,0,.11);
width:440px;max-width:calc(100vw - 32px);padding:44px}
.badge{display:inline-block;background:#f59e0b;color:#201f1e;font-size:11px;font-weight:600;
letter-spacing:.06em;border-radius:4px;padding:3px 8px;margin-bottom:16px}
h1{font-size:28px;font-weight:600;margin:0 0 16px}
.note{color:#605e5c;font-size:12px;margin-top:24px}
.error{background:#fde7e9;color:#a4262c;border-radius:4px;padding:12px 16px;margin-bottom:16px;font-size:14px}
ul.picker{list-style:none;margin:0;padding:0}
ul.picker li{margin:0}
ul.picker button{display:flex;flex-direction:column;width:100%%;text-align:left;background:none;
border:none;border-radius:8px;padding:10px 12px;cursor:pointer;font:inherit}
ul.picker button:hover{background:#f3f2f1}
.upn{color:#605e5c;font-size:12px}
label{display:block;font-size:14px;font-weight:600;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%%;box-sizing:border-box;height:32px;border:1px solid #e1dfdd;
border-radius:4px;padding:6px 8px;font:inherit}
.primary{background:#0078d4;color:#fff;border:none;border-radius:4px;height:32px;padding:8px 20px;
font-size:14px;font-weight:600;cursor:pointer;margin-top:16px;line-height:1}
.primary:hover{background:#106ebe}
.scopes{margin:8px 0 0;padding-left:20px;font-size:14px}
</style></head>
<body><main class="card"><span class="badge">LOCAL EMULATOR</span>%s
<p class="note">Not for production use. Never enter a real password.</p></main></body></html>`

func writeHTML(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, pageShell, html.EscapeString(title), body)
}

func hiddenFields(fields map[string]string) string {
	out := ""
	for k, v := range fields {
		out += fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`,
			html.EscapeString(k), html.EscapeString(v))
	}
	return out
}

// renderAccountPicker lists enabled users as selectable rows posting
// __ee_user back to action.
func (i *Identity) renderAccountPicker(w http.ResponseWriter, action, signedState string,
	users []*store.User, extra map[string]string, errMsg string) {
	body := `<h1>Pick an account</h1>`
	if errMsg != "" {
		body += `<div class="error">` + html.EscapeString(errMsg) + `</div>`
	}
	body += `<ul class="picker">`
	for _, u := range users {
		fields := map[string]string{fieldState: signedState, fieldUser: u.ID}
		for k, v := range extra {
			fields[k] = v
		}
		body += fmt.Sprintf(
			`<li><form method="post" action="%s">%s<button type="submit"><span>%s</span><span class="upn">%s</span></button></form></li>`,
			html.EscapeString(action), hiddenFields(fields),
			html.EscapeString(u.DisplayName), html.EscapeString(u.UserPrincipalName))
	}
	body += `</ul>`
	writeHTML(w, http.StatusOK, "Sign in", body)
}

// renderPasswordForm renders the REQUIRE_PASSWORD username+password form.
func (i *Identity) renderPasswordForm(w http.ResponseWriter, action, signedState string,
	extra map[string]string, prefillUPN, errMsg string) {
	fields := map[string]string{fieldState: signedState}
	for k, v := range extra {
		fields[k] = v
	}
	body := `<h1>Sign in</h1>`
	if errMsg != "" {
		body += `<div class="error">` + html.EscapeString(errMsg) + `</div>`
	}
	body += fmt.Sprintf(`<form method="post" action="%s">%s
<label for="u">Email</label><input id="u" type="text" name="%s" value="%s" autocomplete="username">
<label for="p">Password</label><input id="p" type="password" name="%s" autocomplete="current-password">
<button class="primary" type="submit">Sign in</button></form>`,
		html.EscapeString(action), hiddenFields(fields),
		fieldUsername, html.EscapeString(prefillUPN), fieldPassword)
	writeHTML(w, http.StatusOK, "Sign in", body)
}

func (i *Identity) renderErrorPage(w http.ResponseWriter, status int, title, message string) {
	body := `<h1>` + html.EscapeString(title) + `</h1><div class="error">` +
		html.EscapeString(message) + `</div>`
	writeHTML(w, status, title, body)
}

func (i *Identity) renderSignedOut(w http.ResponseWriter) {
	writeHTML(w, http.StatusOK, "Signed out",
		`<h1>You're signed out</h1><p>It's safe to close this window.</p>`)
}
