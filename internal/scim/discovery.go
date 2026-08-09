package scim

// RFC 7643 §7 discovery resources. These describe exactly the attributes
// userResource / groupResource actually emit and userBody / groupBody actually
// accept — not the full core schemas — so a client that reads them and then
// drives the endpoint sees no surprises.
//
// The attribute definitions matter more than they look: a SCIM client learns
// which attributes are required by reading /Schemas. Publishing schema entries
// without an `attributes` array leaves every real client guessing, which is how
// this gap stayed invisible to our own Go tests — they asserted the collection
// was served, never that it was usable.

// attr builds a singular attribute definition with the common defaults.
func attr(name, typ, mutability string, required bool) map[string]any {
	return map[string]any{
		"name": name, "type": typ, "multiValued": false, "required": required,
		"caseExact": false, "mutability": mutability, "returned": "default",
		"uniqueness": "none",
	}
}

// refAttr builds a reference-typed attribute, which RFC 7643 §7 requires to
// carry referenceTypes.
func refAttr(name, mutability string, refTypes ...string) map[string]any {
	a := attr(name, "reference", mutability, false)
	a["referenceTypes"] = refTypes
	return a
}

func userSchemaDef() map[string]any {
	userName := attr("userName", "string", "readWrite", true)
	userName["uniqueness"] = "server"
	return map[string]any{
		"schemas":     []string{schemaSchema},
		"id":          userSchema,
		"name":        "User",
		"description": "User Account",
		"attributes": []any{
			userName,
			attr("displayName", "string", "readWrite", false),
			attr("active", "boolean", "readWrite", false),
			map[string]any{
				"name": "name", "type": "complex", "multiValued": false, "required": false,
				"mutability": "readWrite", "returned": "default",
				"subAttributes": []any{
					attr("givenName", "string", "readWrite", false),
					attr("familyName", "string", "readWrite", false),
				},
			},
			map[string]any{
				"name": "emails", "type": "complex", "multiValued": true, "required": false,
				"mutability": "readWrite", "returned": "default",
				"subAttributes": []any{
					attr("value", "string", "readWrite", false),
					attr("type", "string", "readWrite", false),
					attr("primary", "boolean", "readWrite", false),
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
}

func groupSchemaDef() map[string]any {
	return map[string]any{
		"schemas":     []string{schemaSchema},
		"id":          groupSchema,
		"name":        "Group",
		"description": "Group",
		"attributes": []any{
			attr("displayName", "string", "readWrite", true),
			map[string]any{
				"name": "members", "type": "complex", "multiValued": true, "required": false,
				"mutability": "readWrite", "returned": "default",
				"subAttributes": []any{
					attr("value", "string", "immutable", false),
					attr("display", "string", "immutable", false),
					// RFC 7643 §7: referenceTypes is REQUIRED when type is
					// "reference". Omitting it makes the attribute undecodable
					// to a client building models from the schema.
					refAttr("$ref", "immutable", "User"),
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
}

// schemaDefs returns the published schemas, keyed by id for the by-id route.
func schemaDefs(b string) map[string]map[string]any {
	out := map[string]map[string]any{
		userSchema:  userSchemaDef(),
		groupSchema: groupSchemaDef(),
	}
	for id, def := range out {
		meta, _ := def["meta"].(map[string]any)
		meta["location"] = b + "/Schemas/" + id
	}
	return out
}

// resourceTypeDefs returns the published resource types, keyed by id.
func resourceTypeDefs(b string) map[string]map[string]any {
	rt := func(id, endpoint, schema string) map[string]any {
		return map[string]any{
			"schemas": []string{resourceTypeSchema}, "id": id, "name": id,
			"description": id, "endpoint": endpoint, "schema": schema,
			"meta": map[string]any{
				"resourceType": "ResourceType",
				"location":     b + "/ResourceTypes/" + id,
			},
		}
	}
	return map[string]map[string]any{
		"User":  rt("User", "/Users", userSchema),
		"Group": rt("Group", "/Groups", groupSchema),
	}
}

// ordered returns defs in a stable order, so the collection responses do not
// shuffle between calls (map iteration order would).
func ordered(defs map[string]map[string]any, ids ...string) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		if d, ok := defs[id]; ok {
			out = append(out, d)
		}
	}
	return out
}
