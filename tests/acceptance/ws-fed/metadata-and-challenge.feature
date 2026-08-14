# US-01 FederationMetadata and US-02 /wsfed challenge — focused scenarios
# Driving ports:
#   GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
#   GET|POST /{tid}/wsfed  (wa=wsignin1.0)
#
# US-01 remaining scenarios are enabled after the walking skeleton (01-01).
# US-02 POST challenge stays @pending until 01-03.

Feature: FederationMetadata names the WS-Fed STS and the challenge reaches it

  @driving_port @real-io @US-01
  Scenario: Signing certificates in both sections match
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given FederationMetadata includes IDPSSODescriptor and a WS-Fed RoleDescriptor
    When Priya compares the signing certificates
    Then the WS-Fed certificate is the same as the SAML certificate

  @driving_port @real-io @US-01
  Scenario: Sign-out is advertised without a sign-out witness
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given Priya fetches FederationMetadata for the Tasks API
    When she reads the WS-Fed RoleDescriptor
    Then the sign-out URL is the same PassiveRequestorEndpoint as sign-in
    And this story does not require a wsignout1.0 round-trip

  @driving_port @real-io @US-01
  Scenario: SAML apps still see their descriptor
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given FederationMetadata already published IDPSSODescriptor for SAML
    When the WS-Fed RoleDescriptor is present
    Then IDPSSODescriptor remains available at the same URL

  @driving_port @real-io @US-01
  Scenario: Metadata fetch stays a saml-metadata audit flow
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    # Driving port: GET /admin/api/audit
    Given Priya fetches the existing FederationMetadata URL
    When the document is served
    Then the audit flow name is saml-metadata
    And the flow is not renamed for WS-Fed

  @driving_port @real-io @US-01
  Scenario: Priya is not sent to a second metadata URL
    # Driving port: GET /{tid}/federationmetadata/2007-06/federationmetadata.xml
    Given Priya's Tasks API already uses MetadataAddress at the existing FederationMetadata URL
    When she points that same URL at the emulator
    Then the WS-Fed RoleDescriptor is on that document
    And she is not required to set MetadataAddress to /wsfed/metadata

  @pending @driving_port @real-io @US-02
  Scenario: POST as well as GET can start sign-in
    # Driving port: POST /{tid}/wsfed wa=wsignin1.0
    Given the Tasks API app is registered with Application ID URI "api://tasks-api"
    And reply URL "https://rp.example.test/signin-wsfed" is registered as wsfed-reply
    When the browser POSTs to /{tid}/wsfed with wa=wsignin1.0, wtrealm=api://tasks-api, and that wreply
    Then the response is not 404
    And unauthenticated callers still see sign-in, not a wresult

  @pending @driving_port @real-io @US-02
  Scenario: Optional context is accepted on the challenge
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given the Finance RP challenges without wctx
    And wtrealm "api://tasks-api" and wreply "https://rp.example.test/signin-wsfed" are registered
    When the browser hits /{tid}/wsfed with wa=wsignin1.0 and that realm and reply
    Then sign-in is shown
    And the later token POST is not required to echo a wctx the RP never sent
