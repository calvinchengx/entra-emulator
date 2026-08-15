package identity

// Well-known first-party Azure Databricks app id. databricks-emulator
// accepts federated JWTs only when aud is this value. Like Fabric, this
// is a compile-time carve-out — no resource app is seeded in the directory.
const databricksFirstPartyAppID = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"

// databricksAud maps the Databricks first-party app id to the audience
// used in issued tokens. Returns "" when the resource is not Databricks.
func databricksAud(resource string) string {
	if resource == databricksFirstPartyAppID {
		return databricksFirstPartyAppID
	}
	return ""
}
