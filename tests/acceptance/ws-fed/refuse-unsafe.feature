# US-06 / US-07 / US-08 refuse-unsafe + KPI-5
# Driving port: GET|POST /{tid}/wsfed
# Guardrail: never Location / wresult POST to an unowned URL
#
# US-06 and US-07 scenarios enabled. US-08 stays @pending until its DELIVER step.

Feature: The STS refuses unsafe WS-Fed challenges

  @driving_port @real-io @US-06 @kpi @KPI-5
  Scenario: Unknown application ID URI does not issue a token to the caller reply
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given no app has Application ID URI "api://not-registered"
    When the browser requests /{tid}/wsfed with wa=wsignin1.0, wtrealm=api://not-registered, and wreply=https://attacker.example.test/steal
    Then the emulator does not POST wresult to "https://attacker.example.test/steal"

  @driving_port @real-io @US-06 @kpi @KPI-5
  Scenario: Empty realm is refused
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given a challenge with wa=wsignin1.0 and no usable wtrealm
    When the browser hits /{tid}/wsfed with wreply "https://attacker.example.test/steal"
    Then no wresult is posted to wreply

  @driving_port @real-io @US-06 @kpi @KPI-5
  Scenario: Unknown realm never redirects to an unowned URL
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given no app has Application ID URI "api://not-registered"
    When the browser requests /{tid}/wsfed with wa=wsignin1.0, wtrealm=api://not-registered, and wreply=https://attacker.example.test/steal
    Then the emulator does not send Location to "https://attacker.example.test/steal"
    And the error stays on the emulator

  @driving_port @real-io @US-07 @kpi @KPI-5
  Scenario: Unregistered reply URL does not receive a token
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Tasks API is registered with wsfed-reply "https://rp.example.test/signin-wsfed" only
    When the browser challenges with wtrealm=api://tasks-api and wreply=https://rp.example.test/not-a-callback
    Then the emulator does not POST wresult to "https://rp.example.test/not-a-callback"

  @driving_port @real-io @US-07 @kpi @KPI-5
  Scenario: Missing reply URL does not receive a token
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given a challenge with wtrealm=api://tasks-api and no wreply
    When the browser hits /{tid}/wsfed
    Then the emulator does not POST wresult to an unregistered or guessed URL

  @driving_port @real-io @US-07 @kpi @KPI-5
  Scenario: Reply registered only as saml-acs is refused
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Tasks API has Application ID URI "api://tasks-api"
    And "https://rp.example.test/acs" is registered only as saml-acs
    When the browser challenges with wtrealm=api://tasks-api and wreply=https://rp.example.test/acs
    Then the emulator does not POST wresult to "https://rp.example.test/acs"

  @driving_port @real-io @US-07 @kpi @KPI-5
  Scenario: Reply registered only as web is refused
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Tasks API has Application ID URI "api://tasks-api"
    And "https://rp.example.test/signin-oidc" is registered only as web
    When the browser challenges with wtrealm=api://tasks-api and wreply=https://rp.example.test/signin-oidc
    Then the emulator does not POST wresult to "https://rp.example.test/signin-oidc"

  @driving_port @real-io @US-07 @kpi @KPI-5
  Scenario: Another app's reply is not accepted
    # Driving port: GET /{tid}/wsfed wa=wsignin1.0
    Given Tasks API owns wsfed-reply "https://rp.example.test/signin-wsfed"
    And Finance API owns wsfed-reply "https://finance.example.test/signin-wsfed"
    When a challenge uses wtrealm=api://tasks-api and Finance's reply URL
    Then Tasks API sign-in does not POST wresult to the Finance reply

  @pending @driving_port @real-io @US-08 @kpi @KPI-5
  Scenario: A token POST that did not start at this STS is refused
    # Driving port: POST /{tid}/wsfed (unsolicited wresult)
    Given no challenge was issued for the Tasks API
    When an actor POSTs wa=wsignin1.0 and a wresult as if sign-in had completed
    Then the emulator does not treat that as a successful sign-in it initiated
    And the Tasks API does not gain a session from that unsolicited token via this STS

  @pending @driving_port @US-08 @kpi @KPI-5
  Scenario: Unsolicited login is not offered as a setting
    # Driving port: GET|POST /{tid}/wsfed
    Given v0.8.0 WS-Fed
    When Priya looks for an allow-unsolicited-logins switch
    Then that behavior is out of this cut
    And no flag is required to refuse unsolicited wresult
