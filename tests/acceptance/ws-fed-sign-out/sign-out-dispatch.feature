# US-02 / US-03 focused dispatch — never mint on wsignout1.0; session actually ends
# Driving port: GET|POST /{tid}/wsfed wa=wsignout1.0
#
# Critical assertion (US-02 / D12): after a completed sign-in (session exists),
# wa=wsignout1.0 must not mint wresult. 302 to https://rp.example.test/wsfed-signed-out.

Feature: Sign-out ends the session and never mints a token

  @driving_port @real-io @property @US-02
  Scenario: Sign-out with a live session does not mint a token
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given Alice (alice@entraemulator.dev) has an emulator session from WS-Fed sign-in
    And the Tasks API has sign-out return "https://rp.example.test/wsfed-signed-out"
    When the browser requests /{tid}/wsfed with wa=wsignout1.0, wtrealm=api://tasks-api, and that return
    Then the emulator does not mint a wresult
    And the browser is not POSTed a RequestSecurityTokenResponse
    And the browser is sent to "https://rp.example.test/wsfed-signed-out"

  @driving_port @real-io @property @US-02
  Scenario: Repeating SignOut with no session still returns to the registered reply
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given the Tasks API session is already gone
    And "https://rp.example.test/wsfed-signed-out" is a registered wsfed-reply for "api://tasks-api"
    When SignOut runs again with wtrealm "api://tasks-api" and that return
    Then the browser is sent to "https://rp.example.test/wsfed-signed-out"
    And the error does not bounce to an unowned URL
    And Priya still has no authenticated Tasks API session

  @driving_port @real-io @US-02
  Scenario: POST as well as GET can sign out
    # Driving port: POST /{tid}/wsfed wa=wsignout1.0
    Given Alice completed WS-Fed sign-in for the Tasks API
    When the browser POSTs to /{tid}/wsfed with wa=wsignout1.0, wtrealm=api://tasks-api, and wreply "https://rp.example.test/wsfed-signed-out"
    Then the emulator does not mint a wresult
    And the browser is sent to "https://rp.example.test/wsfed-signed-out"

  @driving_port @real-io @US-03
  Scenario: After sign-out Alice is still listed
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Alice signed out through wa=wsignout1.0
    When the account picker is shown
    Then Alice (alice@entraemulator.dev) is listed as an enabled account

  @driving_port @real-io @US-03 @US-05
  Scenario: Choosing Alice after sign-out still completes sign-in
    # Driving port: GET|POST /{tid}/wsfed wa=wsignin1.0
    Given the picker is shown after sign-out
    When Priya chooses Alice
    Then the browser POSTs wresult to "https://rp.example.test/signin-wsfed"
    And unmodified WsFederation can establish a Tasks API session again

  @driving_port @real-io @US-02
  Scenario: Unknown wa is refused on the emulator
    # Driving port: GET /{tid}/wsfed (non-empty wa other than wsignin1.0 / wsignout1.0)
    Given the Tasks API is registered with Application ID URI "api://tasks-api"
    When the browser requests /{tid}/wsfed with wa=wsignoutcleanup1.0 and wtrealm=api://tasks-api
    Then the error stays on the emulator
    And no wresult is minted
    And empty wa and wa=wsignin1.0 still start sign-in

  @driving_port @real-io @US-08
  Scenario: Sign-out carrying a token body does not deliver a token
    # Driving port: POST /{tid}/wsfed wa=wsignout1.0 with a wresult body
    Given Alice has an emulator session from WS-Fed sign-in
    When the browser POSTs wa=wsignout1.0 together with a wresult body for wtrealm=api://tasks-api
    Then the emulator does not treat that as a successful token delivery
    And no wresult is minted to the sign-in callback
