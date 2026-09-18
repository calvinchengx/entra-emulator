package store

// Entity types mirror docs/06-data-model-and-seed.md. Timestamps are Unix
// epoch seconds; identifiers are lowercase GUID strings.

type Tenant struct {
	ID            string
	DisplayName   string
	Issuer        string
	InitialDomain string // <slug>.onmicrosoft.com
	CreatedAt     int64
}

// WorkspaceIdentity is a Fabric workspace identity (roadmap #16): an app
// registration + service principal whose credential is emulator-managed and
// whose lifecycle is tied to a Fabric workspace. The SP is the app referenced
// by AppID; ID is the identity's (service-principal) object id.
type WorkspaceIdentity struct {
	ID            string
	TenantID      string
	AppID         string
	WorkspaceID   string
	WorkspaceName string
	State         string // Active | Provisioning | Failed | Deprovisioning
	CreatedAt     int64
}

type User struct {
	ID                string
	TenantID          string
	UserPrincipalName string
	DisplayName       string
	GivenName         string // empty = null
	Surname           string
	Mail              string
	PasswordHash      string
	AccountEnabled    bool
	UserType          string // Member | Guest (B2B)
	ExternalUserState string // guests: PendingAcceptance | Accepted
	// InviteRedirectURL is the guest's post-redemption destination, bound at
	// invitation time. Redemption reads it from here rather than from the
	// redeem link, so the target cannot be swapped by whoever follows the link.
	InviteRedirectURL string
	CreatedAt         int64
	UpdatedAt         int64 // last mutation; drives incremental SCIM sync
}

type Group struct {
	ID          string
	TenantID    string
	DisplayName string
	Description string
	CreatedAt   int64
}

type App struct {
	ID                    string // app_id / client_id
	TenantID              string
	DisplayName           string
	IsConfidential        bool
	AppIDURI              string // empty = null
	OptionalClaims        string // raw JSON or empty
	GroupMembershipClaims string // None|SecurityGroup|DirectoryRole|ApplicationGroup|All
	GroupOverageLimit     int    // 0 = unset (use global default)
	CreatedAt             int64
}

type RedirectURI struct {
	ID    int64
	AppID string
	URI   string
	Type  string // web|spa|native
}

type AppSecret struct {
	ID          string
	AppID       string
	DisplayName string
	SecretHash  string
	Hint        string
	ExpiresAt   int64 // 0 = never
	CreatedAt   int64
}

type AppScope struct {
	ID                      string
	AppID                   string
	Value                   string
	AdminConsentDisplayName string
	IsEnabled               bool
}

type AppRole struct {
	ID                 string
	AppID              string
	Value              string
	DisplayName        string
	AllowedMemberTypes string // CSV: Application,User
	IsEnabled          bool
}

type SigningKey struct {
	Kid          string
	TenantID     string
	Alg          string
	PublicJWK    string // JSON
	PrivatePKCS8 string // PEM
	IsActive     bool
	CreatedAt    int64
	NotAfter     int64 // 0 = none
}

type AuthCode struct {
	Code                string
	AppID               string
	UserID              string
	RedirectURI         string
	Scopes              string // space-delimited
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	AMR                 string // authentication method reference (e.g. "pwd", "fido")
	// AuthTime is when the end-user authenticated for this code (OIDC
	// `auth_time`), carried from the session because the token endpoint is a
	// back-channel call with no cookie to look one up from.
	AuthTime int64
	// MaxAgeRequested records that the authorization request carried `max_age`.
	// OIDC Core 3.1.2.1 makes `auth_time` REQUIRED in that case and merely
	// OPTIONAL otherwise, so the exchange has to know which request it is
	// answering, not just what time authentication happened.
	MaxAgeRequested bool
	ExpiresAt       int64
	Consumed        bool
	CreatedAt       int64
}

type RefreshToken struct {
	TokenHash string // SHA-256 hex of the plaintext; PK
	AppID     string
	UserID    string
	Scopes    string
	Resource  string
	// AMR and AuthTime describe the AUTHENTICATION the chain descends from, as
	// distinct from the grant it carries. Without them a refreshed ID token
	// contradicts the one the code exchange issued: same app, same session,
	// same user, disagreeing about how and when the user authenticated. Every
	// successor inherits them, so they survive arbitrarily many rotations.
	AMR         string
	AuthTime    int64
	ExpiresAt   int64
	RotatedFrom string
	Revoked     bool
	CreatedAt   int64
}

type Session struct {
	ID         string
	UserID     string
	AuthMethod string // "pwd" (default) or "fido"
	CreatedAt  int64
	ExpiresAt  int64
}

// AuthTime is when the end-user actually authenticated, for OIDC's `auth_time`
// claim and for `max_age` staleness.
//
// It is the row's creation time rather than a second column, because every
// session this emulator creates is created AT a credential check and never
// re-authenticated in place: all five callers of createSession sit immediately
// after a password verification, a WebAuthn assertion, a device-code approval,
// or a WS-Fed / SAML sign-in. A duplicate column would be a second source of
// truth that could silently disagree with the first. If a session ever does
// become re-authenticatable in place, this method is the single place that has
// to change.
func (s *Session) AuthTime() int64 { return s.CreatedAt }

type DeviceCode struct {
	DeviceCodeHash string // SHA-256 hex; PK
	UserCode       string
	AppID          string
	UserID         string // set on approval
	Scopes         string
	Status         string // pending|approved|denied|expired
	Interval       int
	ExpiresAt      int64
	CreatedAt      int64
}
