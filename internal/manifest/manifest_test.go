package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

const (
	examplePath = "../../samples/manifest/entra-emulator.manifest.json"
	schemaPath  = "../../schemas/manifest.schema.json"
	tenantID    = "3c8f2a91-6d4e-4b7a-9e15-0a2b7c4d8e6f"
	apiID       = "8a1d5e7c-2f4b-4c9a-b3e6-5d7f9a1c3e2b"
	workerID    = "e5f7a9b1-4c6d-4e8f-a2b4-6c8e0f2a4b6d"
)

func TestExampleManifestLoads(t *testing.T) {
	m, err := Load(examplePath)
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if m.TenantID != tenantID || len(m.Applications) != 4 || len(m.Users) != 2 || len(m.Groups) != 1 {
		t.Fatalf("unexpected example: %+v", m)
	}
}

// TestSchemaMatchesTypes keeps schemas/manifest.schema.json and the Go types
// in step: every object in the schema has exactly the properties its Go type
// decodes, so neither can gain or lose a property alone.
func TestSchemaMatchesTypes(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	defs := schema["$defs"].(map[string]any)
	def := func(name string) map[string]any { return defs[name].(map[string]any) }
	application := def("application")
	api := application["properties"].(map[string]any)["api"].(map[string]any)

	for name, c := range map[string]struct {
		obj map[string]any
		typ any
	}{
		"(root)":            {schema, Manifest{}},
		"tokenLifetimes":    {def("tokenLifetimes"), TokenLifetimes{}},
		"application":       {application, Application{}},
		"application.api":   {api, API{}},
		"clientSecret":      {def("clientSecret"), ClientSecret{}},
		"redirectUris":      {def("redirectUris"), RedirectURIs{}},
		"permissionScope":   {def("permissionScope"), PermissionScope{}},
		"appRole":           {def("appRole"), AppRole{}},
		"user":              {def("user"), User{}},
		"group":             {def("group"), Group{}},
		"appRoleAssignment": {def("appRoleAssignment"), AppRoleAssignment{}},
	} {
		if c.obj["additionalProperties"] != false {
			t.Errorf("%s: schema must set additionalProperties: false, as decoding is strict", name)
		}
		var inSchema []string
		for k := range c.obj["properties"].(map[string]any) {
			inSchema = append(inSchema, k)
		}
		var inGo []string
		rt := reflect.TypeOf(c.typ)
		for i := 0; i < rt.NumField(); i++ {
			inGo = append(inGo, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
		sort.Strings(inSchema)
		sort.Strings(inGo)
		if !slices.Equal(inSchema, inGo) {
			t.Errorf("%s: schema properties %v, Go fields %v", name, inSchema, inGo)
		}
	}
}

func TestValidationNamesThePath(t *testing.T) {
	valid := `"tenantId": "` + tenantID + `"`
	app := `{"appId": "` + apiID + `", "displayName": "API", "appRoles": [{"value": "Admin", "allowedMemberTypes": ["Application"]}]}`
	for _, tc := range []struct{ doc, want string }{
		{`{"tenantId": "contoso"}`, "tenantId: must be a lowercase GUID"},
		{`{` + valid + `, "tennantId": "x"}`, `unknown field "tennantId"`},
		{`{` + valid + `, "applications": [{"appId": "nope", "displayName": "A"}]}`, "applications[0].appId: must be a GUID"},
		{`{` + valid + `, "applications": [` + app + `, ` + app + `]}`, "applications[1].appId: duplicates the id at applications[0].appId"},
		{`{` + valid + `, "applications": [{"appId": "` + apiID + `", "displayName": "A", "identifierUris": ["api://a", "api://b"]}]}`,
			"applications[0].identifierUris: at most one identifier URI is supported"},
		{`{` + valid + `, "applications": [{"appId": "` + apiID + `", "displayName": "A", "appRoles": [{"value": "R", "allowedMemberTypes": ["Robot"]}]}]}`,
			`applications[0].appRoles[0].allowedMemberTypes[0]: must be "User" or "Application"`},
		{`{` + valid + `, "users": [{"userPrincipalName": "alice", "displayName": "Alice"}]}`, "users[0].userPrincipalName: must be a user principal name"},
		{`{` + valid + `, "groups": [{"displayName": "G", "members": ["nobody@contoso.local"]}]}`, `groups[0].members[0]: "nobody@contoso.local" is not a user`},
		{`{` + valid + `, "users": [{"userPrincipalName": "a@c.local", "displayName": "A", "appRoleAssignments": [{"resourceAppId": "` + workerID + `"}]}]}`,
			"users[0].appRoleAssignments[0].resourceAppId: is not an application in this manifest"},
		{`{` + valid + `, "applications": [` + app + `], "users": [{"userPrincipalName": "a@c.local", "displayName": "A", "appRoleAssignments": [{"resourceAppId": "` + apiID + `", "appRole": "Admin"}]}]}`,
			`users[0].appRoleAssignments[0].appRole: role "Admin" does not allow member type User`},
		{`{` + valid + `, "tokenLifetimes": {"accessToken": -5}}`, "tokenLifetimes.accessToken: must be a positive number of seconds"},
	} {
		_, err := Parse([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%s):\n  want error containing %q\n  got %v", tc.doc, tc.want, err)
		}
	}
}

// TestDerivedIDsAreStable: objects without an id get the same GUID on every
// load, and a user's derived id does not depend on the UPN's case.
func TestDerivedIDsAreStable(t *testing.T) {
	doc := func(upn string) []byte {
		return []byte(`{"tenantId": "` + tenantID + `", "users": [{"userPrincipalName": "` + upn + `", "displayName": "A"}]}`)
	}
	ids := make([]string, 0, 3)
	for _, upn := range []string{"alice@contoso.local", "alice@contoso.local", "Alice@Contoso.local"} {
		m, err := Parse(doc(upn))
		if err != nil {
			t.Fatal(err)
		}
		c, _ := m.compile(false)
		ids = append(ids, c.snap.Users[0].ID)
	}
	if ids[0] != ids[1] || ids[0] != ids[2] || !guidRe.MatchString(ids[0]) {
		t.Fatalf("derived ids: %v", ids)
	}
}

func TestApply(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureTenant(tenantID, "https://login.test/"+tenantID+"/v2.0"); err != nil {
		t.Fatal(err)
	}
	// Start from the seeded directory: the manifest must replace it.
	if _, err := st.Seed(tenantID, "https://login.test/"+tenantID+"/v2.0"); err != nil {
		t.Fatal(err)
	}
	m, err := Load(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(st, m); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if _, err := st.GetUserByUPN("alice@entraemulator.dev"); err == nil {
		t.Fatal("seeded user survived the manifest")
	}
	alice, err := st.GetUserByUPN("alice@contoso.local")
	if err != nil || !store.VerifySecret("Password1!", alice.PasswordHash) || !alice.AccountEnabled {
		t.Fatalf("alice: %v %+v", err, alice)
	}

	bff, err := st.GetApp("c2e4f6a8-3b5d-4f7a-9c1e-2d4f6a8b0c3e")
	if err != nil || !bff.IsConfidential {
		t.Fatalf("BFF app: %v %+v", err, bff)
	}
	secrets, _ := st.ListSecrets(bff.ID)
	if len(secrets) != 1 || !store.VerifySecret("bff-dev-secret", secrets[0].SecretHash) || secrets[0].Hint != "bff…et" {
		t.Fatalf("BFF secret: %+v", secrets)
	}
	redirects, _ := st.ListRedirectURIs(bff.ID)
	if len(redirects) != 1 || redirects[0].Type != "web" {
		t.Fatalf("BFF redirects: %+v", redirects)
	}
	if spa, _ := st.ListRedirectURIs("4b6c8d2e-1a3f-4e5b-8c7d-9f0a2b4c6d8e"); len(spa) != 1 || spa[0].Type != "spa" {
		t.Fatalf("SPA redirects: %+v", spa)
	}
	if api, err := st.GetAppByIDURI("api://contoso-api"); err != nil || api.ID != apiID {
		t.Fatalf("API by identifier URI: %v %+v", err, api)
	}

	// Role assignments: the worker's application permission, the group's
	// user role, and Bob's default (role-less) access assignment.
	if roles, has, _ := st.AssignedAppRoleValues(workerID, apiID); !has || !slices.Equal(roles, []string{"Tasks.Read.All"}) {
		t.Fatalf("worker roles: %v %v", has, roles)
	}
	groups, _ := st.ListGroupsForUser(alice.ID)
	if len(groups) != 1 {
		t.Fatalf("alice's groups: %+v", groups)
	}
	if roles, _, _ := st.AssignedAppRoleValues(groups[0].ID, apiID); !slices.Equal(roles, []string{"Tasks.Admin"}) {
		t.Fatalf("group roles: %v", roles)
	}
	bob, _ := st.GetUserByUPN("bob@contoso.local")
	if roles, has, _ := st.AssignedAppRoleValues(bob.ID, apiID); !has || len(roles) != 0 {
		t.Fatalf("bob: want a role-less default assignment, got %v %v", has, roles)
	}

	// Applying a smaller manifest replaces the directory and its assignments.
	m.Users, m.Groups = m.Users[1:], nil
	m.Applications[3].AppRoleAssignments = nil
	if err := Apply(st, m); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if _, err := st.GetUserByUPN("alice@contoso.local"); err == nil {
		t.Fatal("removed user survived re-apply")
	}
	if _, has, _ := st.AssignedAppRoleValues(workerID, apiID); has {
		t.Fatal("removed assignment survived re-apply")
	}
}
