package server

import (
	"net/url"
	"testing"
)

const (
	scimUserURN  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupURN = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// TestSCIMDiscoveryByID covers the by-id discovery routes of RFC 7644 §4.
// The collection endpoints already advertised meta.location for each entry, but
// those links 404'd: our own tests only ever asserted the collections, so a real
// client following the advertised location was the first thing to notice.
func TestSCIMDiscoveryByID(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	for _, id := range []string{"User", "Group"} {
		code, rt := scimReq(t, "GET", base+"/ResourceTypes/"+id, nil)
		if code != 200 || rt["id"] != id {
			t.Fatalf("ResourceTypes/%s: %d %v", id, code, rt)
		}
		meta, _ := rt["meta"].(map[string]any)
		if meta["location"] != base+"/ResourceTypes/"+id {
			t.Fatalf("ResourceTypes/%s location = %v", id, meta["location"])
		}
	}
	if code, _ := scimReq(t, "GET", base+"/ResourceTypes/Nope", nil); code != 404 {
		t.Fatalf("unknown resource type: want 404, got %d", code)
	}

	for _, urn := range []string{scimUserURN, scimGroupURN} {
		code, sc := scimReq(t, "GET", base+"/Schemas/"+url.PathEscape(urn), nil)
		if code != 200 || sc["id"] != urn {
			t.Fatalf("Schemas/%s: %d %v", urn, code, sc)
		}
	}
	if code, _ := scimReq(t, "GET", base+"/Schemas/urn:nope", nil); code != 404 {
		t.Fatalf("unknown schema: want 404, got %d", code)
	}
}

// TestSCIMSchemasCarryAttributes pins the part a client actually consumes. A
// schema served without `attributes` is syntactically fine and useless: it is
// how a client learns userName is required, and publishing entries without it
// left every real client guessing.
func TestSCIMSchemasCarryAttributes(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	required := func(urn string) map[string]bool {
		code, sc := scimReq(t, "GET", base+"/Schemas/"+url.PathEscape(urn), nil)
		if code != 200 {
			t.Fatalf("Schemas/%s: %d", urn, code)
		}
		attrs, _ := sc["attributes"].([]any)
		if len(attrs) == 0 {
			t.Fatalf("Schemas/%s served no attributes", urn)
		}
		out := map[string]bool{}
		for _, a := range attrs {
			m, _ := a.(map[string]any)
			name, _ := m["name"].(string)
			req, _ := m["required"].(bool)
			out[name] = req
		}
		return out
	}

	u := required(scimUserURN)
	if !u["userName"] {
		t.Fatalf("User schema does not mark userName required: %v", u)
	}
	g := required(scimGroupURN)
	if !g["displayName"] {
		t.Fatalf("Group schema does not mark displayName required: %v", g)
	}

	// RFC 7643 §7: referenceTypes is REQUIRED when type is "reference".
	// Without it a client building models from the schema cannot decode the
	// attribute at all, which is a hard failure rather than a cosmetic one.
	code, sc := scimReq(t, "GET", base+"/Schemas/"+url.PathEscape(scimGroupURN), nil)
	if code != 200 {
		t.Fatalf("Schemas/Group: %d", code)
	}
	var checked bool
	for _, a := range sc["attributes"].([]any) {
		m := a.(map[string]any)
		if m["name"] != "members" {
			continue
		}
		for _, s := range m["subAttributes"].([]any) {
			sm := s.(map[string]any)
			if sm["type"] != "reference" {
				continue
			}
			rt, _ := sm["referenceTypes"].([]any)
			if len(rt) == 0 {
				t.Fatalf("reference attribute %v has no referenceTypes", sm["name"])
			}
			checked = true
		}
	}
	if !checked {
		t.Fatal("Group members exposed no reference sub-attribute to check")
	}
}
