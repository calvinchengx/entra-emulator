# US-03 same account picker — focused scenarios
# Driving port: GET|POST /{tid}/wsfed (account picker chrome; POST action /{tid}/wsfed)

Feature: WS-Fed sign-in is the same account picker OIDC and SAML already use

  @driving_port @real-io @US-03
  Scenario: Password-required mode stays the existing form
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given the emulator is already in password-required mode
    When Priya hits a WS-Fed challenge for the Tasks API
    Then she sees the same email and password form OIDC uses
    And she does not see a WS-Fed-specific login page

  @driving_port @real-io @US-03
  Scenario: Challenge parameters survive account choice
    # Driving port: POST /{tid}/wsfed (picker action)
    Given wctx was "tasks-return-state-7" on the Tasks API challenge
    And wtrealm was "api://tasks-api"
    And wreply was "https://rp.example.test/signin-wsfed"
    When Priya chooses Alex Rivera
    Then the completing POST still has wctx "tasks-return-state-7"
    And wtrealm remains "api://tasks-api"
    And wreply remains "https://rp.example.test/signin-wsfed"

  @driving_port @real-io @US-03
  Scenario: Disabled user is not listed as selectable
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Jordan Blake is a disabled user in the workforce tenant
    When Priya looks at Pick an account after a WS-Fed challenge
    Then Jordan Blake is not listed as a selectable account
