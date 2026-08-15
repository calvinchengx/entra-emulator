# US-06 / US-07 / US-08 refuse-unsafe + KPI-3
# Driving port: GET|POST /{tid}/wsfed wa=wsignout1.0
# Guardrail: never Location / wresult POST to an unowned or wrong-type URL
#
# Library-sent wreply must be an exact wsfed-reply. Wrong type (saml-acs, web)
# or unowned URL → 4xx LOCAL EMULATOR, no Location to the caller.

Feature: The STS refuses unsafe WS-Fed sign-out returns

  @driving_port @real-io @US-06 @kpi @KPI-3
  Scenario: Unknown application ID URI does not return the browser to the caller URL
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given the Tasks API is registered as "api://tasks-api"
    When the browser requests /{tid}/wsfed with wa=wsignout1.0, wtrealm=api://not-registered, and wreply=https://attacker.example.test/steal
    Then the error stays on the emulator
    And the response has no Location to "https://attacker.example.test/steal"
    And no wresult is minted

  @driving_port @real-io @US-06 @kpi @KPI-3
  Scenario: Empty realm is refused on sign-out
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given a wsignout1.0 request with empty or omitted wtrealm
    When the emulator answers with wreply "https://attacker.example.test/steal"
    Then the error stays on the emulator
    And the caller-supplied wreply does not receive the browser

  @driving_port @real-io @US-07 @kpi @KPI-3
  Scenario: A SAML ACS is not accepted as a sign-out return
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given "https://rp.example.test/acs" is registered only as saml-acs
    When wsignout1.0 names that URL as the return
    Then the error stays on the emulator
    And the browser is not sent to the ACS

  @driving_port @real-io @US-07 @kpi @KPI-3
  Scenario: An OIDC web callback is not accepted as a sign-out return
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given "https://rp.example.test/signin-oidc" is registered only as web
    When wsignout1.0 names that URL as the return
    Then the error stays on the emulator

  @driving_port @real-io @US-07 @kpi @KPI-3
  Scenario: Another app's reply is not accepted
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given Finance API has wsfed-reply "https://finance.example.test/signin-wsfed"
    When Tasks API sign-out (wtrealm=api://tasks-api) names Finance's reply as the return
    Then the error stays on the emulator

  @driving_port @real-io @US-07 @kpi @KPI-3
  Scenario: Unregistered return does not receive the browser
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    When wsignout1.0 names "https://rp.example.test/not-a-callback" as the return
    Then the error stays on the emulator
    And there is no Location to that URL

  @driving_port @real-io @US-07
  Scenario: Missing return uses a registered wsfed-reply
    # Driving port: GET /{tid}/wsfed wa=wsignout1.0
    Given the Tasks API has registered wsfed-reply "https://rp.example.test/signin-wsfed" and "https://rp.example.test/wsfed-signed-out"
    When wsignout1.0 names wtrealm=api://tasks-api and omits the return URL
    Then the browser is sent to a registered wsfed-reply for that app
    And the emulator does not pick a saml-acs or web URI on the same app
    And no wresult is minted

  @pending @driving_port @real-io @US-08 @kpi @KPI-3
  Scenario: A token POST that did not start at this STS is still refused
    # Driving port: POST /{tid}/wsfed (unsolicited wresult)
    Given the Tasks API is registered
    When the browser POSTs a wresult to /{tid}/wsfed without a challenge this STS issued
    Then the emulator refuses
    And no Tasks API session is created via this STS

  @pending @driving_port @real-io @US-08
  Scenario: SOAP stays absent
    # Driving port: no SOAP / active WS-Trust route
    When a client calls a SOAP / active WS-Trust path on the emulator
    Then the response is not a working SOAP listener
    And no SOAP sign-out is offered

  @pending @driving_port @US-08
  Scenario: Unsolicited login is still not offered as a setting
    # Driving port: GET|POST /{tid}/wsfed
    Given this sign-out cut
    When Priya looks for an allow-unsolicited-logins switch
    Then the emulator still does not offer an unsolicited-login flag
