package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// TestCustomSecurityAttributes covers tenant-defined typed metadata: attribute
// sets, definitions, and assignment onto a user. The word doing the work is
// TYPED — an Integer attribute must refuse a string, or "typed metadata" is
// just a map.
func TestCustomSecurityAttributes(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	dir := hts.URL + "/graph/v1.0/directory"

	code, set := postJSONAuth(t, dir+"/attributeSets", app, map[string]any{
		"id": "Engineering", "description": "Engineering attributes", "maxAttributesPerSet": 25,
	})
	if code != http.StatusCreated {
		t.Fatalf("create attribute set: %d %v", code, set)
	}

	// One of each type, plus a collection.
	for _, d := range []map[string]any{
		{"attributeSet": "Engineering", "name": "Project", "type": "String"},
		{"attributeSet": "Engineering", "name": "CostCenter", "type": "Integer"},
		{"attributeSet": "Engineering", "name": "OnCall", "type": "Boolean"},
		{"attributeSet": "Engineering", "name": "Tags", "type": "String", "isCollection": true},
	} {
		if code, body := postJSONAuth(t, dir+"/customSecurityAttributeDefinitions", app, d); code != http.StatusCreated {
			t.Fatalf("create definition %v: %d %v", d["name"], code, body)
		}
	}

	t.Run("definition ids are the set_name composite", func(t *testing.T) {
		status, one := graphGet(t, hts.URL, "/graph/v1.0/directory/customSecurityAttributeDefinitions/Engineering_Project", app)
		if status != http.StatusOK {
			t.Fatalf("get definition: %d %v", status, one)
		}
		if one["attributeSet"] != "Engineering" || one["name"] != "Project" || one["type"] != "String" {
			t.Fatalf("definition shape: %v", one)
		}
	})

	t.Run("values assign and read back, grouped by set", func(t *testing.T) {
		code, _ := patchJSONAuth(t, hts.URL+"/graph/v1.0/users/"+aliceID, app, map[string]any{
			"customSecurityAttributes": map[string]any{
				"Engineering": map[string]any{
					"Project": "Apollo", "CostCenter": 1001, "OnCall": true,
					"Tags": []string{"backend", "oncall"},
				},
			},
		})
		// Graph answers PATCH /users/{id} with 204 No Content.
		if code != http.StatusNoContent {
			t.Fatalf("assign attributes: want 204, got %d", code)
		}
		status, u := graphGet(t, hts.URL,
			"/graph/v1.0/users/"+aliceID+"?$select=id,customSecurityAttributes", app)
		if status != http.StatusOK {
			t.Fatalf("read back: %d %v", status, u)
		}
		csa, _ := u["customSecurityAttributes"].(map[string]any)
		eng, _ := csa["Engineering"].(map[string]any)
		if eng["Project"] != "Apollo" || eng["CostCenter"] != float64(1001) || eng["OnCall"] != true {
			t.Fatalf("values did not round-trip: %v", eng)
		}
		if tags, _ := eng["Tags"].([]any); len(tags) != 2 {
			t.Fatalf("collection did not round-trip: %v", eng["Tags"])
		}
	})

	t.Run("not returned unless explicitly selected, as in Graph", func(t *testing.T) {
		status, u := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID, app)
		if status != http.StatusOK {
			t.Fatalf("get user: %d", status)
		}
		if _, present := u["customSecurityAttributes"]; present {
			t.Errorf("Graph returns customSecurityAttributes only on $select; it leaked by default")
		}
	})

	t.Run("the declared type is enforced", func(t *testing.T) {
		// An Integer attribute must refuse a string.
		if code, _ := patchJSONAuth(t, hts.URL+"/graph/v1.0/users/"+aliceID, app, map[string]any{
			"customSecurityAttributes": map[string]any{
				"Engineering": map[string]any{"CostCenter": "not-a-number"},
			},
		}); code != http.StatusBadRequest {
			t.Errorf("a String value for an Integer attribute must be refused, got %d", code)
		}
		// A scalar for a collection attribute must be refused too.
		if code, _ := patchJSONAuth(t, hts.URL+"/graph/v1.0/users/"+aliceID, app, map[string]any{
			"customSecurityAttributes": map[string]any{
				"Engineering": map[string]any{"Tags": "just-one"},
			},
		}); code != http.StatusBadRequest {
			t.Errorf("a scalar for a collection attribute must be refused, got %d", code)
		}
	})

	t.Run("validation of sets and definitions", func(t *testing.T) {
		if code, _ := postJSONAuth(t, dir+"/customSecurityAttributeDefinitions", app, map[string]any{
			"attributeSet": "NoSuchSet", "name": "X", "type": "String",
		}); code != http.StatusBadRequest {
			t.Errorf("a definition in a nonexistent set must be refused, got %d", code)
		}
		if code, _ := postJSONAuth(t, dir+"/customSecurityAttributeDefinitions", app, map[string]any{
			"attributeSet": "Engineering", "name": "Weird", "type": "Decimal",
		}); code != http.StatusBadRequest {
			t.Errorf("an unsupported type must be refused, got %d", code)
		}
	})
}

// patchJSONAuth PATCHes a JSON body with a bearer token (Graph write surface).
func patchJSONAuth(t *testing.T, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPatch, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
