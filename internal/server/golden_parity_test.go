package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Golden-reference parity tests. They boot the emulator in-process and assert
// its live discovery / Graph / SCIM responses conform to the canonical
// references captured under e2e/golden/. See e2e/golden/README.md for what
// "parity" means (contract conformance + no drift, not byte-identical).

func goldenPath(name string) string {
	return filepath.Join("..", "..", "e2e", "golden", name)
}

func loadGolden(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(goldenPath(name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse golden %s: %v", name, err)
	}
	return m
}

// asStrings converts a JSON array (golden or live) into []string.
func asStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// missingFrom returns elements of want not present in have.
func missingFrom(have, want []string) []string {
	h := toSet(have)
	var miss []string
	for _, w := range want {
		if !h[w] {
			miss = append(miss, w)
		}
	}
	return miss
}

// notSubset returns elements of got that are not in allowed.
func notSubset(got, allowed []string) []string {
	a := toSet(allowed)
	var extra []string
	for _, g := range got {
		if !a[g] {
			extra = append(extra, g)
		}
	}
	return extra
}

func sameSet(a, b []string) bool {
	return len(missingFrom(a, b)) == 0 && len(missingFrom(b, a)) == 0
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstSchema(m map[string]any) string {
	s := asStrings(m["schemas"])
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// TestGoldenParityOIDCDiscovery diffs the emulator's discovery document against
// the real Entra discovery contract: required fields present, protocol enums a
// compatible subset, documented divergences reported.
func TestGoldenParityOIDCDiscovery(t *testing.T) {
	hts, _, _ := newTestServer(t)
	golden := loadGolden(t, "oidc-discovery.golden.json")

	resp, err := http.Get(hts.URL + "/" + tenant + "/v2.0/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}

	for _, f := range asStrings(golden["required_fields"]) {
		if _, ok := doc[f]; !ok {
			t.Errorf("discovery missing required field %q", f)
		}
	}

	pv, _ := golden["protocol_values"].(map[string]any)

	if got, want := asStrings(doc["subject_types_supported"]), asStrings(pv["subject_types_supported_equals"]); !sameSet(got, want) {
		t.Errorf("subject_types_supported = %v, want %v", got, want)
	}
	if miss := missingFrom(asStrings(doc["id_token_signing_alg_values_supported"]), asStrings(pv["id_token_signing_alg_values_must_include"])); len(miss) > 0 {
		t.Errorf("id_token_signing_alg_values_supported missing %v", miss)
	}
	if extra := notSubset(asStrings(doc["response_types_supported"]), asStrings(pv["response_types_supported_subset_of"])); len(extra) > 0 {
		t.Errorf("response_types_supported has values Entra does not advertise: %v", extra)
	}
	if extra := notSubset(asStrings(doc["response_modes_supported"]), asStrings(pv["response_modes_supported_subset_of"])); len(extra) > 0 {
		t.Errorf("response_modes_supported has values Entra does not advertise: %v", extra)
	}
	if miss := missingFrom(asStrings(doc["scopes_supported"]), asStrings(pv["scopes_supported_must_include"])); len(miss) > 0 {
		t.Errorf("scopes_supported missing OIDC core %v", miss)
	}
	if extra := notSubset(asStrings(doc["token_endpoint_auth_methods_supported"]), asStrings(pv["token_endpoint_auth_methods_subset_of"])); len(extra) > 0 {
		t.Errorf("token_endpoint_auth_methods_supported has values Entra does not advertise: %v", extra)
	}
	if miss := missingFrom(asStrings(doc["claims_supported"]), asStrings(pv["claims_supported_must_include"])); len(miss) > 0 {
		t.Errorf("claims_supported missing core %v", miss)
	}

	// Informational: the documented divergences (Entra advertises, we omit).
	var omitted []string
	for _, f := range asStrings(golden["entra_only_fields_out_of_scope"]) {
		if _, ok := doc[f]; !ok {
			omitted = append(omitted, f)
		}
	}
	if len(omitted) > 0 {
		t.Logf("documented divergences (Entra advertises, emulator omits by design): %v", omitted)
	}
}

// TestGoldenParityGraph asserts each Graph resource emits EXACTLY the golden
// property set — no invented, renamed, or dropped properties (schema drift).
func TestGoldenParityGraph(t *testing.T) {
	hts, _, _ := newTestServer(t)
	golden := loadGolden(t, "graph-resources.golden.json")
	resources, _ := golden["resources"].(map[string]any)
	app := appGraphToken(t, hts.URL)

	cases := []struct{ resource, path string }{
		{"user", "/graph/v1.0/users"},
		{"group", "/graph/v1.0/groups"},
		{"application", "/graph/v1.0/applications"},
		{"servicePrincipal", "/graph/v1.0/servicePrincipals"},
	}
	for _, c := range cases {
		status, list := graphGet(t, hts.URL, c.path, app)
		if status != http.StatusOK {
			t.Errorf("%s: list status %d", c.resource, status)
			continue
		}
		vals, _ := list["value"].([]any)
		if len(vals) == 0 {
			t.Errorf("%s: empty list, cannot check shape", c.resource)
			continue
		}
		entity, _ := vals[0].(map[string]any)
		got := sortedKeys(entity)
		spec, _ := resources[c.resource].(map[string]any)
		want := asStrings(spec["properties"])
		sort.Strings(want)
		if !sameSet(got, want) {
			t.Errorf("%s Graph property drift:\n  emulator: %v\n  golden:   %v\n  extra:    %v\n  missing:  %v",
				c.resource, got, want, notSubset(got, want), missingFrom(got, want))
		}
	}
}

// TestGoldenParitySCIM asserts the emulator's SCIM responses use the exact RFC
// 7643/7644 schema URNs and carry the required attributes.
func TestGoldenParitySCIM(t *testing.T) {
	hts, _, _ := newTestServer(t)
	golden := loadGolden(t, "scim-schemas.golden.json")
	urns, _ := golden["schema_urns"].(map[string]any)
	req, _ := golden["required_attributes"].(map[string]any)
	metaTypes, _ := golden["meta_resource_types"].(map[string]any)
	base := hts.URL + "/scim/v2"

	if _, spc := scimReq(t, "GET", base+"/ServiceProviderConfig", nil); firstSchema(spc) != urns["serviceProviderConfig"] {
		t.Errorf("ServiceProviderConfig schema = %q, want %q", firstSchema(spc), urns["serviceProviderConfig"])
	}
	if _, rt := scimReq(t, "GET", base+"/ResourceTypes", nil); firstSchema(rt) != urns["listResponse"] {
		t.Errorf("ResourceTypes schema = %q, want %q", firstSchema(rt), urns["listResponse"])
	}

	// Users list → ListResponse with required attributes.
	_, users := scimReq(t, "GET", base+"/Users", nil)
	if firstSchema(users) != urns["listResponse"] {
		t.Errorf("Users list schema = %q, want %q", firstSchema(users), urns["listResponse"])
	}
	for _, a := range asStrings(req["listResponse"]) {
		if _, ok := users[a]; !ok {
			t.Errorf("Users ListResponse missing attribute %q", a)
		}
	}

	resources, _ := users["Resources"].([]any)
	if len(resources) == 0 {
		t.Fatal("no seeded SCIM users to inspect")
	}
	user, _ := resources[0].(map[string]any)
	if firstSchema(user) != urns["user"] {
		t.Errorf("User schema = %q, want %q", firstSchema(user), urns["user"])
	}
	for _, a := range asStrings(req["user"]) {
		if _, ok := user[a]; !ok {
			t.Errorf("User missing required attribute %q", a)
		}
	}
	if meta, _ := user["meta"].(map[string]any); meta["resourceType"] != metaTypes["user"] {
		t.Errorf("User meta.resourceType = %v, want %v", meta["resourceType"], metaTypes["user"])
	}

	// A Group resource, if any are seeded.
	_, groups := scimReq(t, "GET", base+"/Groups", nil)
	if gres, _ := groups["Resources"].([]any); len(gres) > 0 {
		group, _ := gres[0].(map[string]any)
		if firstSchema(group) != urns["group"] {
			t.Errorf("Group schema = %q, want %q", firstSchema(group), urns["group"])
		}
		for _, a := range asStrings(req["group"]) {
			if _, ok := group[a]; !ok {
				t.Errorf("Group missing required attribute %q", a)
			}
		}
	}
}
