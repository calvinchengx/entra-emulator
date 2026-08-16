# US-01 metadata guardrail + US-05 existing federation still works
# Driving ports:
#   GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
#   GET /{tid}/wsfed/metadata (must stay 404)
#   existing OIDC authorize and e2e/saml (same suites, not a new witness)
#
# Do not keep signOutForbiddenTrip as the sign-out story. These scenarios
# prove the advertised URL did not move while wsignout1.0 is driven elsewhere.

Feature: FederationMetadata still names sign-out on the existing STS

  @driving_port @real-io @US-01
  Scenario: Federation metadata still names the sign-out URL on the sign-in endpoint
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given the emulator already serves FederationMetadata at the existing URL
    When Priya's Tasks API fetches that document as MetadataAddress
    Then PassiveRequestorEndpoint is "/{tid}/wsfed"
    And SecurityTokenServiceEndpoint is the same URL
    And sign-out is advertised on that PassiveRequestorEndpoint

  @driving_port @real-io @US-01 @US-05
  Scenario: SAML apps still see their descriptor after sign-out is witnessed
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given FederationMetadata includes a WS-Fed RoleDescriptor
    When a SAML app reads the same document
    Then IDPSSODescriptor is still present
    And SAML single sign-on still names "/{tid}/saml2"

  @driving_port @real-io @US-01
  Scenario: Priya is not sent to a second metadata URL for sign-out
    # Driving port: GET /{tid}/wsfed/metadata
    Given Priya's MetadataAddress is the existing FederationMetadata URL
    When anyone requests GET /{tid}/wsfed/metadata
    Then the response is not a second metadata document
    And Priya is not required to discover a new sign-out URL

  @driving_port @real-io @US-05
  Scenario: Existing SAML sign-in still completes
    # Driving port: existing SAML SSO on the same emulator
    Given FederationMetadata includes the WS-Fed RoleDescriptor
    And the emulator answers wa=wsignout1.0 on /{tid}/wsfed
    When a SAML app signs in on the same emulator
    Then the assertion still posts to the registered ACS

  @driving_port @real-io @US-05
  Scenario: Existing OIDC sign-in still completes
    # Driving port: existing OIDC authorize on the same emulator
    Given the same emulator that answers wa=wsignout1.0
    When the existing OIDC SPA completes authorize
    Then it still receives ID and access tokens
