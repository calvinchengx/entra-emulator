package graph

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Graph permission enforcement. Real Entra gates every Graph operation on the
// caller's permissions: a delegated call must carry the scope in `scp`, an
// app-only call the app role in `roles`, and a token that lacks it gets
// 403 Authorization_RequestDenied — not a 200.
//
// The emulator enforces the same gate when GRAPH_PERMISSIONS is on. It is off
// by default because the emulator has always let any valid Graph-audience token
// through, and turning it on unannounced would break existing setups; switch it
// on to test that your app actually requests the permissions it needs.

// perms lists the permissions that satisfy one operation. Any ONE of them is
// enough (as in real Graph), and the Directory.* pair are the supersets.
type perms struct {
	delegated []string
	app       []string
}

// Read/write permission sets per resource family, mirroring the Graph
// permissions reference.
var (
	userRead = perms{
		delegated: []string{"User.ReadBasic.All", "User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		app:       []string{"User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
	}
	userWrite = perms{
		delegated: []string{"User.ReadWrite.All", "Directory.ReadWrite.All"},
		app:       []string{"User.ReadWrite.All", "Directory.ReadWrite.All"},
	}
	groupRead = perms{
		delegated: []string{"Group.Read.All", "Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		app:       []string{"Group.Read.All", "Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
	}
	groupWrite = perms{
		delegated: []string{"Group.ReadWrite.All", "Directory.ReadWrite.All"},
		app:       []string{"Group.ReadWrite.All", "Directory.ReadWrite.All"},
	}
	appRead = perms{
		delegated: []string{"Application.Read.All", "Application.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		app:       []string{"Application.Read.All", "Application.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
	}
	appWrite = perms{
		delegated: []string{"Application.ReadWrite.All", "Directory.ReadWrite.All"},
		app:       []string{"Application.ReadWrite.All", "Directory.ReadWrite.All"},
	}
	roleRead = perms{
		delegated: []string{"RoleManagement.Read.Directory", "RoleManagement.ReadWrite.Directory", "Directory.Read.All", "Directory.ReadWrite.All"},
		app:       []string{"RoleManagement.Read.Directory", "RoleManagement.ReadWrite.Directory", "Directory.Read.All", "Directory.ReadWrite.All"},
	}
	roleWrite = perms{
		delegated: []string{"RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"},
		app:       []string{"RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"},
	}
	// /me is delegated-only; User.Read is the minimum a signed-in user needs.
	meRead = perms{
		delegated: []string{"User.Read", "User.ReadWrite", "User.ReadBasic.All", "User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
	}
)

// graphRequirement maps a request to the permissions that satisfy it. res is
// the path after the version segment ("users", "groups/{id}/members", …).
// An empty perms means "unmapped — no additional requirement".
func graphRequirement(method, res string) perms {
	head := res
	if i := strings.IndexByte(head, '/'); i >= 0 {
		head = head[:i]
	}
	write := method != http.MethodGet && method != http.MethodHead
	switch head {
	case "me":
		return meRead
	case "users":
		if write {
			return userWrite
		}
		return userRead
	case "groups":
		if write {
			return groupWrite
		}
		return groupRead
	case "applications", "servicePrincipals":
		if write {
			return appWrite
		}
		return appRead
	case "invitations":
		return perms{
			delegated: []string{"User.Invite.All", "User.ReadWrite.All", "Directory.ReadWrite.All"},
			app:       []string{"User.Invite.All", "User.ReadWrite.All", "Directory.ReadWrite.All"},
		}
	case "roleManagement":
		if write {
			return roleWrite
		}
		return roleRead
	case "directory": // deletedItems (recycle bin)
		if write {
			return perms{delegated: []string{"Directory.ReadWrite.All"}, app: []string{"Directory.ReadWrite.All"}}
		}
		return perms{
			delegated: []string{"Directory.Read.All", "Directory.ReadWrite.All"},
			app:       []string{"Directory.Read.All", "Directory.ReadWrite.All"},
		}
	case "oauth2PermissionGrants":
		if write {
			return perms{
				delegated: []string{"DelegatedPermissionGrant.ReadWrite.All", "Directory.ReadWrite.All"},
				app:       []string{"DelegatedPermissionGrant.ReadWrite.All", "Directory.ReadWrite.All"},
			}
		}
		return perms{
			delegated: []string{"DelegatedPermissionGrant.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
			app:       []string{"DelegatedPermissionGrant.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		}
	default:
		return perms{}
	}
}

// resourcePath returns the Graph path after the version segment.
func resourcePath(p string) (string, bool) {
	const v1 = "/v1.0/"
	i := strings.Index(p, v1)
	if i < 0 {
		return "", false
	}
	return p[i+len(v1):], true
}

// tokenRoles reads the `roles` claim (app-only permissions).
func tokenRoles(tok *tokens.ValidatedToken) []string {
	raw, _ := tok.Claims["roles"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func hasAny(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// permissionDenied reports the 403 message when the caller lacks the permission
// this operation requires, or "" when the call is allowed. Always allows when
// enforcement is off.
func (g *Graph) permissionDenied(r *http.Request, tok *tokens.ValidatedToken) string {
	if !g.Cfg.GraphPermissions {
		return ""
	}
	res, ok := resourcePath(r.URL.Path)
	if !ok {
		return "" // non-versioned surface (e.g. /oidc/userinfo) has its own gate
	}
	req := graphRequirement(r.Method, res)

	if tok.OID != "" { // delegated
		if len(req.delegated) == 0 || hasAny(tok.Scopes, req.delegated) {
			return ""
		}
		return "Insufficient privileges to complete the operation. The delegated token needs one of: " +
			strings.Join(req.delegated, ", ") + "."
	}
	// App-only. A resource with no app permissions is delegated-only, and the
	// route's own gate rejects it — don't double-handle here.
	if len(req.app) == 0 || hasAny(tokenRoles(tok), req.app) {
		return ""
	}
	return "Insufficient privileges to complete the operation. The app-only token needs one of: " +
		strings.Join(req.app, ", ") + "."
}
