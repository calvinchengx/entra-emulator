# Walking skeleton — Priya signs Alice out of the Tasks API at the local STS
# Feature: ws-fed-sign-out | Date: 15 Aug 2026
# Strategy C (Real local): real SQLite, real HTTP, real .NET stranger. No containers.
#
# Driving ports:
#   GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
#   GET|POST /{tid}/wsfed  (wa=wsignout1.0 after completed wsignin1.0)
#   e2e/wsfed unmodified Microsoft.AspNetCore.Authentication.WsFederation SignOut (KPI-1)
#
# WS-1 (clean) is enabled. WS-2 (with-pre-commit), WS-3 (with-stale-config),
# and KPI-1 (e2e/wsfed SignOut) are @pending until DELIVER.
#
# Return URL (DESIGN): https://rp.example.test/wsfed-signed-out
# Sign-in callback remains https://rp.example.test/signin-wsfed
# SignOutWreply ≠ CallbackPath. Do not mix into tests/acceptance/ws-fed/.

Feature: Sign out of a WS-Fed relying party at the local STS

  @walking_skeleton @real-io @driving_adapter @driving_port @US-01 @US-02 @US-03
  Scenario: Priya signs Alice out of the Tasks API on a clean emulator
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    # Driving port: GET|POST /{tid}/wsfed wa=wsignout1.0
    # Environment: clean
    Given a clean emulator directory
    And the emulator has an app whose Application ID URI is "api://tasks-api"
    And that app has a registered wsfed-reply "https://rp.example.test/signin-wsfed"
    And that app has a distinct registered wsfed-reply "https://rp.example.test/wsfed-signed-out"
    And Alice (alice@entraemulator.dev) completed WS-Fed sign-in for the Tasks API
    When unmodified SignOut drives wa=wsignout1.0 to the advertised PassiveRequestorEndpoint with wtrealm "api://tasks-api" and wreply "https://rp.example.test/wsfed-signed-out"
    Then FederationMetadata at the existing URL still names PassiveRequestorEndpoint as "/{tid}/wsfed"
    And the emulator does not mint a wresult
    And the browser is sent to registered wsfed-reply "https://rp.example.test/wsfed-signed-out"
    And Alice's emulator session is gone
    And the next wa=wsignin1.0 from that browser shows Pick an account, not a wresult
    And Alice (alice@entraemulator.dev) is listed

  @pending @walking_skeleton @real-io @driving_adapter @driving_port @US-05
  Scenario: Priya signs Alice out alongside existing OIDC and SAML
    # Driving port: GET|POST /{tid}/wsfed wa=wsignout1.0
    # Environment: with-pre-commit
    Given the emulator already has OIDC and SAML sign-in configured
    And the Tasks API app is registered with Application ID URI "api://tasks-api", wsfed-reply "https://rp.example.test/signin-wsfed", and sign-out return "https://rp.example.test/wsfed-signed-out"
    And Alice completed WS-Fed sign-in for the Tasks API
    When wa=wsignout1.0 completes against the advertised endpoint
    Then Alice's emulator session is gone
    And existing OIDC and SAML sign-in still complete on the same emulator

  @pending @walking_skeleton @real-io @driving_adapter @driving_port @US-07
  Scenario: Priya signs Alice out after registering a distinct sign-out return on a stale directory
    # Driving port: GET|POST /{tid}/wsfed wa=wsignout1.0
    # Environment: with-stale-config
    Given a stale emulator directory whose Tasks API has a sign-in reply but no distinct sign-out return
    And the Tasks API exists with Application ID URI "api://tasks-api" and wsfed-reply "https://rp.example.test/signin-wsfed" only
    When Priya registers wsfed-reply "https://rp.example.test/wsfed-signed-out" and Alice signs out with that return
    Then the browser is sent to "https://rp.example.test/wsfed-signed-out"
    And the emulator never mints a wresult
    And the emulator never sends the browser to an unregistered return

  @pending @walking_skeleton @kpi @real-io @driving_adapter @driving_port @US-02 @US-03 @US-05 @KPI-1
  Scenario: Priya's unmodified WsFederation middleware completes SignOut
    # Driving port: e2e/wsfed stranger — unmodified Microsoft.AspNetCore.Authentication.WsFederation SignOut
    # Witness: python3 e2e/run.py wsfed including a SignOut step. DELIVER extends e2e/wsfed.
    # Contract: two wsfed-reply URIs; SignOutWreply ≠ CallbackPath.
    Given Priya pointed MetadataAddress and Wtrealm at the emulator
    And she did not modify Microsoft.AspNetCore.Authentication.WsFederation
    And the Tasks API registers wsfed-reply "https://rp.example.test/signin-wsfed" and "https://rp.example.test/wsfed-signed-out"
    And library SignOutWreply is the distinct sign-out return, not the sign-in callback
    And Alice completed emulator sign-in for the Tasks API
    When unmodified SignOut runs
    Then Priya no longer has an authenticated session at the Tasks API
    And the next challenge shows Pick an account
    And v0.8.0 sign-in in the same stranger run still completes
