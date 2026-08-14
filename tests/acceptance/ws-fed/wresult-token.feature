# US-04 wresult token shape — focused scenarios
# Driving port: browser auto-POST wresult to registered wsfed-reply
# (STS completes via GET|POST /{tid}/wsfed after picker)

Feature: The Tasks API receives a SAML 2.0 wresult at its registered reply

  @driving_port @real-io @US-04
  Scenario: Token audience matches the application ID URI
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given wtrealm was "api://tasks-api"
    When wresult is posted after Alex Rivera signs in
    Then the assertion Audience is "api://tasks-api"

  @driving_port @real-io @US-04
  Scenario: Issuer matches federation metadata
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given FederationMetadata entityID is the emulator login origin for {tid}
    When wresult is posted after Alex Rivera signs in
    Then the assertion Issuer equals that entityID

  @driving_port @real-io @US-04
  Scenario: Context is echoed unchanged
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given the challenge included wctx "tasks-return-state-7"
    When wresult is posted
    Then wctx is "tasks-return-state-7"

  @driving_port @real-io @US-04
  Scenario: Omitted context stays omitted
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given the Finance RP challenge omitted wctx
    When wresult is posted
    Then the POST does not require a wctx field the RP never sent

  @driving_port @real-io @US-04
  Scenario: Assertion version is SAML 2.0 for this witness
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given the Tasks API Wtrealm is Application ID URI "api://tasks-api"
    When wresult is issued
    Then TokenType is SAML 2.0 ending in #SAMLV2.0
    And the inner assertion Version is "2.0"
    And the assertion is not SAML 1.1

  @driving_port @real-io @US-04
  Scenario: NameID format is persistent
    # Driving port: auto-POST wresult to registered wsfed-reply
    Given Alex Rivera completed Tasks API sign-in
    When wresult is posted
    Then NameID format is persistent
