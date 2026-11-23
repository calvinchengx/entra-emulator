// Package manifest loads a declarative JSON description of the directory:
// one tenant, its applications, users and groups, their app-role assignments,
// and token lifetimes. When the emulator is given a manifest (MANIFEST_FILE),
// the manifest replaces the directory at startup instead of the
// deterministic seed, and its tenant and token lifetimes replace the
// TENANT_ID and TOKEN_LIFETIME_* settings. The JSON Schema is
// schemas/manifest.schema.json; property names follow Microsoft Graph's
// application and user resources.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Manifest is the root document.
type Manifest struct {
	Schema         string          `json:"$schema,omitempty"`
	TenantID       string          `json:"tenantId"`
	TokenLifetimes *TokenLifetimes `json:"tokenLifetimes,omitempty"`
	Applications   []Application   `json:"applications,omitempty"`
	Users          []User          `json:"users,omitempty"`
	Groups         []Group         `json:"groups,omitempty"`
}

// TokenLifetimes in seconds; zero means the built-in default.
type TokenLifetimes struct {
	AuthCode     int `json:"authCode,omitempty"`
	IDToken      int `json:"idToken,omitempty"`
	AccessToken  int `json:"accessToken,omitempty"`
	RefreshToken int `json:"refreshToken,omitempty"`
	DeviceCode   int `json:"deviceCode,omitempty"`
}

// Application is an app registration, which is also its own service
// principal. It is confidential when it has client secrets.
type Application struct {
	AppID                 string              `json:"appId"`
	DisplayName           string              `json:"displayName"`
	IdentifierURIs        []string            `json:"identifierUris,omitempty"`
	ClientSecrets         []ClientSecret      `json:"clientSecrets,omitempty"`
	Web                   *RedirectURIs       `json:"web,omitempty"`
	Spa                   *RedirectURIs       `json:"spa,omitempty"`
	PublicClient          *RedirectURIs       `json:"publicClient,omitempty"`
	API                   *API                `json:"api,omitempty"`
	AppRoles              []AppRole           `json:"appRoles,omitempty"`
	GroupMembershipClaims string              `json:"groupMembershipClaims,omitempty"`
	AppRoleAssignments    []AppRoleAssignment `json:"appRoleAssignments,omitempty"`
}

// ClientSecret is a client secret given in plain text; it is stored hashed.
type ClientSecret struct {
	DisplayName string `json:"displayName,omitempty"`
	Value       string `json:"value"`
}

// RedirectURIs is Graph's web / spa / publicClient platform object.
type RedirectURIs struct {
	RedirectURIs []string `json:"redirectUris,omitempty"`
}

// API is Graph's application.api.
type API struct {
	OAuth2PermissionScopes []PermissionScope `json:"oauth2PermissionScopes,omitempty"`
}

// PermissionScope is a delegated permission the app exposes.
type PermissionScope struct {
	ID                      string `json:"id,omitempty"`
	Value                   string `json:"value"`
	AdminConsentDisplayName string `json:"adminConsentDisplayName,omitempty"`
	IsEnabled               *bool  `json:"isEnabled,omitempty"`
}

// AppRole is a role the app defines for users, groups or applications.
type AppRole struct {
	ID                 string   `json:"id,omitempty"`
	Value              string   `json:"value"`
	DisplayName        string   `json:"displayName,omitempty"`
	AllowedMemberTypes []string `json:"allowedMemberTypes"`
	IsEnabled          *bool    `json:"isEnabled,omitempty"`
}

// User is a directory user.
type User struct {
	ID                 string              `json:"id,omitempty"`
	UserPrincipalName  string              `json:"userPrincipalName"`
	DisplayName        string              `json:"displayName"`
	GivenName          string              `json:"givenName,omitempty"`
	Surname            string              `json:"surname,omitempty"`
	Mail               string              `json:"mail,omitempty"`
	Password           string              `json:"password,omitempty"`
	AccountEnabled     *bool               `json:"accountEnabled,omitempty"`
	AppRoleAssignments []AppRoleAssignment `json:"appRoleAssignments,omitempty"`
}

// Group is a security group with direct user members.
type Group struct {
	ID                 string              `json:"id,omitempty"`
	DisplayName        string              `json:"displayName"`
	Description        string              `json:"description,omitempty"`
	Members            []string            `json:"members,omitempty"`
	AppRoleAssignments []AppRoleAssignment `json:"appRoleAssignments,omitempty"`
}

// AppRoleAssignment grants the holder (the enclosing user, group or
// application) a role defined by another application. AppRole is the role's
// value; when it is empty the assignment is the default access assignment,
// which carries no role.
type AppRoleAssignment struct {
	ResourceAppID string `json:"resourceAppId"`
	AppRole       string `json:"appRole,omitempty"`
}

// Load reads, strictly decodes and validates the manifest at path. Unknown
// properties are errors, so a misspelt property is reported rather than
// ignored. Every validation problem is reported, each prefixed with its JSON
// path.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Parse strictly decodes and validates a manifest document.
func Parse(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("invalid JSON: data after the manifest object")
	}
	m.TenantID = strings.ToLower(m.TenantID)
	if _, errs := m.compile(false); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return &m, nil
}

// Apply replaces the store's directory with the manifest's applications,
// users, groups and app-role assignments, in one transaction. Secrets and
// passwords are hashed here.
func Apply(st *store.Store, m *Manifest) error {
	c, errs := m.compile(true)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return st.ReplaceDirectory(c.snap, m.TenantID, c.assignments)
}

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var groupMembershipClaims = map[string]bool{
	"None": true, "SecurityGroup": true, "DirectoryRole": true, "ApplicationGroup": true, "All": true,
}

type compiled struct {
	snap        *store.DirectorySnapshot
	assignments []*store.AppRoleAssignment
}

// compile validates the manifest and converts it to a directory snapshot.
// With hash false (validation only) secrets and passwords are not hashed.
func (m *Manifest) compile(hash bool) (*compiled, []string) {
	var errs []string
	fail := func(path, format string, args ...any) {
		errs = append(errs, path+": "+fmt.Sprintf(format, args...))
	}
	hashed := func(path, plain string) string {
		if !hash {
			return ""
		}
		h, err := store.HashSecret(plain)
		if err != nil {
			fail(path, "%v", err)
		}
		return h
	}

	if !guidRe.MatchString(m.TenantID) {
		fail("tenantId", "must be a lowercase GUID")
	}
	if lt := m.TokenLifetimes; lt != nil {
		for name, v := range map[string]int{"authCode": lt.AuthCode, "idToken": lt.IDToken,
			"accessToken": lt.AccessToken, "refreshToken": lt.RefreshToken, "deviceCode": lt.DeviceCode} {
			if v < 0 {
				fail("tokenLifetimes."+name, "must be a positive number of seconds")
			}
		}
	}

	c := &compiled{snap: &store.DirectorySnapshot{Version: 1}}
	objectIDs := map[string]string{} // id -> JSON path; ids are unique across object types
	claim := func(id, path string) {
		if prev, ok := objectIDs[id]; ok {
			fail(path, "duplicates the id at %s", prev)
		}
		objectIDs[id] = path
	}

	// Applications first: assignments elsewhere refer to their roles.
	type appRoles struct{ byValue map[string]*store.AppRole }
	apps := map[string]appRoles{}
	identifierURIs := map[string]string{}
	for i, a := range m.Applications {
		p := fmt.Sprintf("applications[%d]", i)
		appID := strings.ToLower(a.AppID)
		if !guidRe.MatchString(appID) {
			fail(p+".appId", "must be a GUID")
		} else {
			claim(appID, p+".appId")
		}
		if a.DisplayName == "" {
			fail(p+".displayName", "is required")
		}
		gmc := a.GroupMembershipClaims
		if gmc == "" {
			gmc = "None"
		} else if !groupMembershipClaims[gmc] {
			fail(p+".groupMembershipClaims", "must be None, SecurityGroup, DirectoryRole, ApplicationGroup or All")
		}
		app := &store.App{ID: appID, TenantID: m.TenantID, DisplayName: a.DisplayName,
			IsConfidential: len(a.ClientSecrets) > 0, GroupMembershipClaims: gmc}
		if len(a.IdentifierURIs) > 1 {
			fail(p+".identifierUris", "at most one identifier URI is supported")
		}
		for j, uri := range a.IdentifierURIs {
			if uri == "" {
				fail(fmt.Sprintf("%s.identifierUris[%d]", p, j), "must not be empty")
				continue
			}
			if prev, ok := identifierURIs[uri]; ok {
				fail(fmt.Sprintf("%s.identifierUris[%d]", p, j), "duplicates %s", prev)
			}
			identifierURIs[uri] = fmt.Sprintf("%s.identifierUris[%d]", p, j)
			if j == 0 {
				app.AppIDURI = uri
			}
		}
		ae := store.AppExport{App: app}

		for j, s := range a.ClientSecrets {
			sp := fmt.Sprintf("%s.clientSecrets[%d]", p, j)
			if s.Value == "" {
				fail(sp+".value", "is required")
				continue
			}
			ae.Secrets = append(ae.Secrets, &store.AppSecret{
				ID: derivedGUID(m.TenantID, "secret", appID, fmt.Sprint(j)), AppID: appID,
				DisplayName: s.DisplayName, SecretHash: hashed(sp+".value", s.Value), Hint: store.SecretHint(s.Value),
			})
		}

		redirects := map[string]bool{}
		for _, platform := range []struct {
			name, kind string
			set        *RedirectURIs
		}{{"web", "web", a.Web}, {"spa", "spa", a.Spa}, {"publicClient", "native", a.PublicClient}} {
			if platform.set == nil {
				continue
			}
			for j, uri := range platform.set.RedirectURIs {
				rp := fmt.Sprintf("%s.%s.redirectUris[%d]", p, platform.name, j)
				if uri == "" {
					fail(rp, "must not be empty")
				} else if redirects[uri] {
					fail(rp, "duplicates another redirect URI of this application")
				}
				redirects[uri] = true
				ae.RedirectURIs = append(ae.RedirectURIs, &store.RedirectURI{AppID: appID, URI: uri, Type: platform.kind})
			}
		}

		if a.API != nil {
			seen := map[string]bool{}
			for j, s := range a.API.OAuth2PermissionScopes {
				sp := fmt.Sprintf("%s.api.oauth2PermissionScopes[%d]", p, j)
				if s.Value == "" {
					fail(sp+".value", "is required")
				} else if seen[s.Value] {
					fail(sp+".value", "duplicates another scope of this application")
				}
				seen[s.Value] = true
				id := strings.ToLower(s.ID)
				if id == "" {
					id = derivedGUID(m.TenantID, "scope", appID, s.Value)
				} else if !guidRe.MatchString(id) {
					fail(sp+".id", "must be a GUID")
				}
				ae.Scopes = append(ae.Scopes, &store.AppScope{ID: id, AppID: appID, Value: s.Value,
					AdminConsentDisplayName: s.AdminConsentDisplayName, IsEnabled: enabled(s.IsEnabled)})
			}
		}

		roles := appRoles{byValue: map[string]*store.AppRole{}}
		for j, r := range a.AppRoles {
			rp := fmt.Sprintf("%s.appRoles[%d]", p, j)
			if r.Value == "" {
				fail(rp+".value", "is required")
			} else if roles.byValue[r.Value] != nil {
				fail(rp+".value", "duplicates another role of this application")
			}
			if len(r.AllowedMemberTypes) == 0 {
				fail(rp+".allowedMemberTypes", "needs \"User\", \"Application\" or both")
			}
			for k, t := range r.AllowedMemberTypes {
				if t != "User" && t != "Application" {
					fail(fmt.Sprintf("%s.allowedMemberTypes[%d]", rp, k), "must be \"User\" or \"Application\"")
				}
			}
			id := strings.ToLower(r.ID)
			if id == "" {
				id = derivedGUID(m.TenantID, "role", appID, r.Value)
			} else if !guidRe.MatchString(id) {
				fail(rp+".id", "must be a GUID")
			}
			role := &store.AppRole{ID: id, AppID: appID, Value: r.Value, DisplayName: r.DisplayName,
				AllowedMemberTypes: strings.Join(r.AllowedMemberTypes, ","), IsEnabled: enabled(r.IsEnabled)}
			roles.byValue[r.Value] = role
			ae.Roles = append(ae.Roles, role)
		}
		apps[appID] = roles
		c.snap.Apps = append(c.snap.Apps, ae)
	}

	// assign resolves an assignment held by principalID. memberType is the
	// allowedMemberTypes value the role must permit ("User" covers groups).
	assigned := map[string]bool{}
	assign := func(path, principalID, principalType, memberType string, a AppRoleAssignment) {
		resource := strings.ToLower(a.ResourceAppID)
		roles, ok := apps[resource]
		if !ok {
			fail(path+".resourceAppId", "is not an application in this manifest")
			return
		}
		roleID := store.ZeroGUID
		if a.AppRole != "" {
			role := roles.byValue[a.AppRole]
			if role == nil {
				fail(path+".appRole", "is not a role of application %s", resource)
				return
			}
			if !strings.Contains(","+role.AllowedMemberTypes+",", ","+memberType+",") {
				fail(path+".appRole", "role %q does not allow member type %s", a.AppRole, memberType)
				return
			}
			roleID = role.ID
		}
		id := derivedGUID(m.TenantID, "assignment", principalID, resource, roleID)
		if assigned[id] {
			return // the same assignment listed twice is one assignment
		}
		assigned[id] = true
		c.assignments = append(c.assignments, &store.AppRoleAssignment{
			ID: id, PrincipalID: principalID, PrincipalType: principalType, ResourceID: resource, AppRoleID: roleID,
		})
	}
	for i, a := range m.Applications {
		for j, ra := range a.AppRoleAssignments {
			assign(fmt.Sprintf("applications[%d].appRoleAssignments[%d]", i, j),
				strings.ToLower(a.AppID), "ServicePrincipal", "Application", ra)
		}
	}

	usersByKey := map[string]string{} // lower(UPN) and id -> id
	for i, u := range m.Users {
		p := fmt.Sprintf("users[%d]", i)
		upn := strings.ToLower(u.UserPrincipalName)
		if upn == "" || !strings.Contains(upn, "@") {
			fail(p+".userPrincipalName", "must be a user principal name, such as alice@contoso.local")
		} else if _, dup := usersByKey[upn]; dup {
			fail(p+".userPrincipalName", "duplicates another user")
		}
		if u.DisplayName == "" {
			fail(p+".displayName", "is required")
		}
		id := strings.ToLower(u.ID)
		if id == "" {
			id = derivedGUID(m.TenantID, "user", upn)
		} else if !guidRe.MatchString(id) {
			fail(p+".id", "must be a GUID")
		}
		claim(id, p+".id")
		usersByKey[upn], usersByKey[id] = id, id
		su := &store.User{ID: id, TenantID: m.TenantID, UserPrincipalName: u.UserPrincipalName,
			DisplayName: u.DisplayName, GivenName: u.GivenName, Surname: u.Surname, Mail: u.Mail,
			AccountEnabled: enabled(u.AccountEnabled)}
		if u.Password != "" {
			su.PasswordHash = hashed(p+".password", u.Password)
		}
		c.snap.Users = append(c.snap.Users, su)
		for j, ra := range u.AppRoleAssignments {
			assign(fmt.Sprintf("%s.appRoleAssignments[%d]", p, j), id, "User", "User", ra)
		}
	}

	for i, g := range m.Groups {
		p := fmt.Sprintf("groups[%d]", i)
		if g.DisplayName == "" {
			fail(p+".displayName", "is required")
		}
		id := strings.ToLower(g.ID)
		if id == "" {
			id = derivedGUID(m.TenantID, "group", g.DisplayName)
		} else if !guidRe.MatchString(id) {
			fail(p+".id", "must be a GUID")
		}
		claim(id, p+".id")
		c.snap.Groups = append(c.snap.Groups, &store.Group{ID: id, TenantID: m.TenantID,
			DisplayName: g.DisplayName, Description: g.Description})
		for j, member := range g.Members {
			userID, ok := usersByKey[strings.ToLower(member)]
			if !ok {
				fail(fmt.Sprintf("%s.members[%d]", p, j), "%q is not a user in this manifest (use a userPrincipalName or id)", member)
				continue
			}
			c.snap.GroupMembers = append(c.snap.GroupMembers, store.GroupMembership{GroupID: id, UserID: userID})
		}
		for j, ra := range g.AppRoleAssignments {
			assign(fmt.Sprintf("%s.appRoleAssignments[%d]", p, j), id, "Group", "User", ra)
		}
	}
	return c, errs
}

func enabled(v *bool) bool { return v == nil || *v }

// derivedGUID returns a stable, name-based GUID for an object the manifest
// does not give an id, so ids survive restarts and tokens issued before a
// restart keep naming the same objects.
func derivedGUID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50 // version 5 (name-based)
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
