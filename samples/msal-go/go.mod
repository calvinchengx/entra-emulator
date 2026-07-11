// Isolated module so the MSAL Go dependency doesn't reach the emulator binary.
module github.com/calvinchengx/entra-emulator/samples/msal-go

go 1.25.11

require github.com/AzureAD/microsoft-authentication-library-for-go v1.7.2

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
)
