# Auditability (rank 1) — Admin + Graph projection for sign-out
# Driving ports:
#   GET /admin/api/audit
#   GET /{tid}/v1.0/auditLogs/signIns  (compat origin: GET /graph/v1.0/auditLogs/signIns)
# Exchanges under test enter through GET|POST /{tid}/wsfed wa=wsignout1.0.
#
# Flow=wsfed, ClientID=wtrealm, no raw wresult. No second log store.

Feature: WS-Fed sign-out appears in the existing audit lists

  @driving_port @real-io @kpi @US-04 @KPI-2
  Scenario: Successful sign-out is recorded without a token body
    # Driving port: GET /admin/api/audit
    Given Alice completed WS-Fed sign-in for wtrealm "api://tasks-api"
    When wa=wsignout1.0 completes
    Then Admin audit includes a wsfed event for that exchange
    And ClientID is "api://tasks-api"
    And the event does not contain raw wresult

  @driving_port @real-io @US-04
  Scenario: Graph sign-ins still treat WS-Fed as interactive
    # Driving port: GET /{tid}/v1.0/auditLogs/signIns
    Given the sign-out exchange was recorded with Flow=wsfed
    When Priya lists Graph auditLogs/signIns
    Then WS-Fed browser exchanges remain interactive
    And no second log store is required to see them

  @driving_port @real-io @kpi @US-04 @US-06 @KPI-2
  Scenario: A refused sign-out is recorded with a concrete reason
    # Driving port: GET /admin/api/audit
    Given a sign-out request with wtrealm=api://not-registered
    When the emulator refuses it
    Then Admin audit includes a failed wsfed event
    And the event carries a concrete reason
    And the event JSON does not contain wresult
