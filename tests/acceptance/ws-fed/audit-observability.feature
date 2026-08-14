# Auditability (rank 1) — Admin + Graph projection
# Driving ports:
#   GET /admin/api/audit
#   GET /{tid}/v1.0/auditLogs/signIns  (compat origin: GET /graph/v1.0/auditLogs/signIns)
# Exchanges under test enter through GET|POST /{tid}/wsfed.
#
# Driving-port Go tests: internal/server/wsfed_walking_skeleton_test.go
# (TestWSFedChallengeAndSuccessAppearInAudit, TestRefusedChallengeIsRecordedWithReason,
# TestGraphSignInsIdentifyTasksAPIAsInteractive).

Feature: WS-Fed exchanges appear in the existing audit lists

  @driving_port @real-io @US-02 @US-04
  Scenario: Challenge and successful sign-in are recorded without a token body
    # Driving port: GET /admin/api/audit
    # Driving port: GET /{tid}/v1.0/auditLogs/signIns
    Given Priya completes Tasks API WS-Fed sign-in as Alex Rivera with wtrealm "api://tasks-api"
    When she lists audit events
    Then an admin audit event records the unauthenticated challenge with flow wsfed and ClientID "api://tasks-api" and no user
    And an admin audit event records success with flow wsfed, ClientID "api://tasks-api", and Alex Rivera
    And neither event includes wresult or the assertion body

  @driving_port @real-io @US-06 @US-07 @US-08
  Scenario: A refused challenge is recorded with a concrete reason
    # Driving port: GET /admin/api/audit
    Given no app has Application ID URI "api://not-registered"
    When the browser challenges /{tid}/wsfed with that wtrealm and wreply "https://attacker.example.test/steal"
    Then an admin audit event records failure with flow wsfed
    And the event carries a concrete Reason
    And the event does not include wresult

  @driving_port @real-io @US-02 @US-04
  Scenario: Graph sign-ins identify the Tasks API and mark the exchange interactive
    # Driving port: GET /{tid}/v1.0/auditLogs/signIns
    Given Priya completed Tasks API WS-Fed sign-in with wtrealm "api://tasks-api"
    When she lists Graph sign-ins
    Then the sign-in row identifies the Tasks API when ClientID is Application ID URI "api://tasks-api"
    And appDisplayName is not blank
    And the exchange is interactive
    And the row does not include wresult
