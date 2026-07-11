package store

// Entity types mirror docs/03-data-model-and-seed.md. Timestamps are Unix
// epoch seconds; identifiers are lowercase GUID strings.

type Tenant struct {
	ID            string
	DisplayName   string
	Issuer        string
	InitialDomain string // <slug>.onmicrosoft.com
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
	CreatedAt         int64
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
	ExpiresAt           int64
	Consumed            bool
	CreatedAt           int64
}

type RefreshToken struct {
	TokenHash   string // SHA-256 hex of the plaintext; PK
	AppID       string
	UserID      string
	Scopes      string
	Resource    string
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
