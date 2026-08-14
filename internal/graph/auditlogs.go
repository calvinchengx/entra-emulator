package graph

import (
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/audit"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// auditLogs/signIns over the emulator's real flow recorder. Every row here is
// an exchange that actually happened — the same events the admin API and portal
// show — reshaped into Graph's signIn resource, so a log consumer (a SIEM
// shipper, a reporting job) can be developed against real traffic.
//
// Scope, stated plainly: the emulator records SIGN-INS (authorize/token
// exchanges). It does not journal directory mutations, so
// auditLogs/directoryAudits is not served rather than served empty.

func (g *Graph) registerAuditLogs(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("GET "+prefix+"/v1.0/auditLogs/signIns", g.requireBearer(g.listSignIns))
	mux.HandleFunc("GET "+prefix+"/v1.0/auditLogs/directoryAudits", g.requireBearer(g.listDirectoryAudits))
}

// signInShape maps a recorded exchange onto Graph's signIn resource.
func (g *Graph) signInShape(e audit.Event) map[string]any {
	// Graph reports success as errorCode 0; failures carry a non-zero code and
	// the concrete reason, which is exactly what the recorder already keeps.
	status := map[string]any{"errorCode": 0, "failureReason": nil, "additionalDetails": nil}
	if !e.OK {
		status["errorCode"] = 50000 // generic AADSTS bucket; the reason carries the detail
		status["failureReason"] = e.Reason
		status["additionalDetails"] = e.Error
	}
	created := e.TimeISO
	if created == "" {
		created = time.Unix(e.Time, 0).UTC().Format(time.RFC3339)
	}
	appName := ""
	app, err := g.Store.GetApp(e.ClientID)
	if err != nil {
		app, err = g.Store.GetAppByIDURI(e.ClientID)
	}
	if err == nil {
		appName = app.DisplayName
	}
	// Interactive means a human was at the keyboard: authorize or WS-Fed
	// passive sign-in, not a back-channel token exchange.
	interactive := e.Flow == "authorize" || e.Flow == "wsfed"

	return map[string]any{
		"id":                      e.ID(),
		"createdDateTime":         created,
		"userId":                  nullable(e.UserID),
		"userPrincipalName":       nullable(e.UserPrincipalName),
		"userDisplayName":         nullable(e.UserPrincipalName),
		"appId":                   nullable(e.ClientID),
		"appDisplayName":          nullable(appName),
		"clientAppUsed":           clientAppUsed(e),
		"isInteractive":           interactive,
		"resourceDisplayName":     nullable(e.GrantType),
		"correlationId":           e.ID(),
		"conditionalAccessStatus": "notApplied", // no CA engine — see docs/parity.md
		"status":                  status,
	}
}

// clientAppUsed reports the grant in Graph's vocabulary where one maps, so the
// field is not an invented value.
func clientAppUsed(e audit.Event) string {
	switch e.GrantType {
	case "password":
		return "Resource Owner Password Credential"
	case "client_credentials":
		return "Client Credentials"
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
		return "Device Code"
	case "authorization_code", "refresh_token":
		return "Browser"
	}
	if e.Flow == "authorize" {
		return "Browser"
	}
	return "Other"
}

func (g *Graph) listSignIns(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	top, _ := paging(r)
	events := g.Audit.List(top)
	shapes := make([]map[string]any, 0, len(events))
	for _, e := range events {
		shapes = append(shapes, g.signInShape(e))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": g.contextURL("auditLogs/signIns"),
		"value":          shapes,
	})
}

// ---- directory audits ----

// recordChange journals a directory mutation with the caller from the token.
// Called from the Graph write handlers, so the actor is always known.
func (g *Graph) recordChange(tok *tokens.ValidatedToken, activity, category, targetType, targetID, targetName string) {
	if g.DirAudit == nil {
		return
	}
	e := audit.DirectoryEvent{
		Time: g.Store.Now(), Activity: activity, Category: category, Result: "success",
		TargetType: targetType, TargetID: targetID, TargetDisplayName: targetName,
	}
	if tok != nil {
		if appID, _ := tok.Claims["appid"].(string); appID != "" {
			e.InitiatedByAppID = appID
		}
		e.InitiatedByUser = tok.OID
		if upn, _ := tok.Claims["preferred_username"].(string); upn != "" {
			e.InitiatedByUPN = upn
		}
	}
	g.DirAudit.Record(e)
}

func (g *Graph) directoryAuditShape(e audit.DirectoryEvent) map[string]any {
	initiatedBy := map[string]any{}
	if e.InitiatedByAppID != "" {
		initiatedBy["app"] = map[string]any{"appId": e.InitiatedByAppID}
	}
	if e.InitiatedByUser != "" {
		initiatedBy["user"] = map[string]any{
			"id": e.InitiatedByUser, "userPrincipalName": nullable(e.InitiatedByUPN),
		}
	}
	return map[string]any{
		"id":                  e.EventID,
		"activityDateTime":    e.TimeISO,
		"activityDisplayName": e.Activity,
		"category":            e.Category,
		"result":              e.Result,
		"initiatedBy":         initiatedBy,
		"targetResources": []any{map[string]any{
			"id": e.TargetID, "type": e.TargetType, "displayName": nullable(e.TargetDisplayName),
		}},
	}
}

func (g *Graph) listDirectoryAudits(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	top, _ := paging(r)
	events := g.DirAudit.List(top)
	shapes := make([]map[string]any, 0, len(events))
	for _, e := range events {
		shapes = append(shapes, g.directoryAuditShape(e))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": g.contextURL("auditLogs/directoryAudits"),
		"value":          shapes,
	})
}
