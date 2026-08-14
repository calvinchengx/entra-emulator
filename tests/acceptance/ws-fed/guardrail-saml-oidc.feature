# US-05 / ADR-001 guardrail — existing OIDC and SAML still pass after metadata growth
# Driving ports:
#   GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
#   existing OIDC authorize and e2e/saml (same suites, not a new witness)
#
# Guardrail: same SAML and OIDC suites after FederationMetadata grows a WS-Fed RoleDescriptor.

Feature: Growing FederationMetadata does not break OIDC or SAML

  @driving_port @real-io @US-01 @US-05
  Scenario: Existing SAML sign-in still completes after WS-Fed metadata growth
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    # Guardrail: e2e/saml (unmodified @node-saml/node-saml)
    Given FederationMetadata includes a WS-Fed RoleDescriptor
    When CI runs the existing SAML sign-in suite
    Then that suite still completes
    And IDPSSODescriptor remains on the same FederationMetadata URL

  @driving_port @real-io @US-05
  Scenario: Existing OIDC sign-in still completes
    # Driving port: existing OIDC authorize on the same emulator
    Given WS-Fed sign-in is available
    When Priya or CI runs an existing OIDC sign-in against the same emulator
    Then that flow still completes
