# Walking skeleton — Priya points the Tasks API at the local STS
# Feature: ws-fed | Date: 14 Aug 2026
# Strategy C (Real local): real SQLite, real HTTP, real .NET stranger. No containers.
#
# Driving ports:
#   GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
#   GET|POST /{tid}/wsfed  (wa=wsignin1.0)
#   account picker POST action /{tid}/wsfed
#   browser auto-POST wresult to registered wsfed-reply
#   e2e/wsfed unmodified Microsoft.AspNetCore.Authentication.WsFederation (KPI-1)
#
# First scenario is enabled. Remaining scenarios are @pending (one-at-a-time).

Feature: Point a WS-Fed relying party at the local STS

  @walking_skeleton @real-io @driving_adapter @driving_port @US-01 @US-02 @US-03 @US-04
  Scenario: Priya completes Tasks API WS-Fed sign-in on a clean emulator
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    # Driving port: GET|POST /{tid}/wsfed wa=wsignin1.0
    # Environment: clean
    Given a clean emulator directory
    And the emulator has an app whose Application ID URI is "api://tasks-api"
    And that app has a registered wsfed-reply "https://rp.example.test/signin-wsfed"
    And Alex Rivera is an enabled user in the workforce tenant
    When Priya points the Tasks API at the existing FederationMetadata URL with Wtrealm "api://tasks-api" and completes sign-in as Alex Rivera with wctx "tasks-return-state-7"
    Then FederationMetadata at the existing URL includes a WS-Fed RoleDescriptor
    And PassiveRequestorEndpoint is "/{tid}/wsfed"
    And SecurityTokenServiceEndpoint is "/{tid}/wsfed"
    And the WS-Fed signing certificate matches the SAML signing certificate
    And the challenge at /{tid}/wsfed with wa=wsignin1.0 is login HTML, not 404 and not a wresult
    And Priya sees the same Pick an account chrome as OIDC and SAML with the LOCAL EMULATOR badge
    And the picker POST action is /{tid}/wsfed
    And the browser POSTs wa=wsignin1.0 and wresult wrapping a SAML 2.0 assertion to "https://rp.example.test/signin-wsfed"
    And the assertion Audience is "api://tasks-api"
    And the assertion Issuer equals FederationMetadata entityID
    And wctx is "tasks-return-state-7"
    And NameID format is persistent

  @pending @walking_skeleton @real-io @driving_adapter @driving_port @US-01 @US-05
  Scenario: Priya completes Tasks API WS-Fed sign-in alongside existing OIDC and SAML
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    # Driving port: GET|POST /{tid}/wsfed wa=wsignin1.0
    # Environment: with-pre-commit
    Given the emulator already has OIDC and SAML sign-in configured
    And the Tasks API app is registered with Application ID URI "api://tasks-api" and wsfed-reply "https://rp.example.test/signin-wsfed"
    When Priya completes WS-Fed sign-in as Alex Rivera for the Tasks API
    Then the Tasks API receives a SAML 2.0 wresult at its registered reply
    And existing OIDC and SAML sign-in still complete on the same emulator

  @pending @walking_skeleton @real-io @driving_adapter @driving_port @US-01 @US-07
  Scenario: Priya completes Tasks API WS-Fed sign-in after registering a reply on a stale directory
    # Driving port: GET|POST /{tid}/wsfed wa=wsignin1.0
    # Environment: with-stale-config
    Given a stale emulator directory whose FederationMetadata was SAML-only
    And the Tasks API exists with Application ID URI "api://tasks-api" but only a web redirect, not a wsfed-reply
    When Priya registers wsfed-reply "https://rp.example.test/signin-wsfed" and completes sign-in as Alex Rivera
    Then the browser POSTs wresult to "https://rp.example.test/signin-wsfed"
    And the emulator never POSTs wresult to the web-only redirect

  @pending @walking_skeleton @kpi @real-io @driving_adapter @driving_port @US-05 @KPI-1
  Scenario: Priya's unmodified WsFederation middleware completes sign-in
    # Driving port: e2e/wsfed stranger — unmodified Microsoft.AspNetCore.Authentication.WsFederation
    # Witness is pending until DELIVER US-05. See e2e/wsfed/README.md.
    Given Priya pointed MetadataAddress and Wtrealm at the emulator
    And she did not modify Microsoft.AspNetCore.Authentication.WsFederation
    And she changed only host and TLS knobs versus Entra
    When Alex Rivera completes emulator sign-in for the Tasks API
    Then the unmodified middleware accepts the token
    And Priya has an authenticated session at the Tasks API
    And the v0.8.0 witness is that library completing metadata fetch plus sign-in
