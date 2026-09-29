# SOC Incident Investigation Report

## 1. Executive Summary

This investigation analyzed anomalous authentication activity associated with a Microsoft Entra identity used for security and administrative operations.

The investigation identified programmatic authentication activity associated with **Python Requests 2.33.0** and **Microsoft Cloud App Security**. Authentication-processing telemetry also contained the OAuth permission:

```text
Application.ReadWrite.All
```

Because this permission can support application-management operations, the activity was investigated further through session correlation, Microsoft Graph API audit telemetry, and administrative audit logs.

The investigation did **not** establish confirmed malicious use or account compromise from the available telemetry.

### Final Disposition

**Anomalous authentication activity — unconfirmed maliciousness**

---

## 2. Investigation Objective

The investigation was designed to determine whether the observed authentication activity indicated:

- Unauthorized account use
- OAuth token abuse
- Application modification
- Persistence
- Privilege abuse
- Confirmed account compromise

The investigation followed an evidence-driven SOC workflow rather than treating the initial anomaly as proof of compromise.

---

## 3. Investigation Scope

### Investigation Window

```text
26 September 2026 – 30 September 2026
```

The primary observed activity occurred between 26 September and 29 September 2026.

### Primary Identity

The investigation focused on the affected/observed Microsoft Entra account used in the lab environment.

Sensitive identity information has been redacted from the public portfolio version.

### Primary Technologies

- Microsoft Defender XDR
- Microsoft Defender Advanced Hunting
- Microsoft Entra ID
- Kusto Query Language (KQL)
- Microsoft Graph API audit telemetry
- Microsoft Entra Audit Logs

---

## 4. Detection and Initial Observation

The investigation began with a baseline analysis of the account's Microsoft Entra sign-in activity.

The baseline query returned:

| Metric | Result |
|---|---:|
| Total events | 4,669 |
| Python-related events | 13 |

The presence of Python-based authentication was considered anomalous because the observed identity was also associated with Microsoft security and administrative services.

Python Requests itself is a legitimate automation library and therefore was treated as an indicator requiring investigation rather than as proof of malicious activity.

---

## 5. Investigation Methodology

The investigation followed these stages:

```text
1. Account Baseline
       ↓
2. Python Authentication Analysis
       ↓
3. OAuth Permission Analysis
       ↓
4. Session Correlation
       ↓
5. Graph API Audit Investigation
       ↓
6. Administrative Audit Investigation
       ↓
7. Impact Assessment
       ↓
8. Final Disposition
```

---

# 6. Investigation Findings

## 6.1 Account Baseline

The account baseline established the overall authentication volume and provided a reference point for identifying unusual client behavior.

The current query returned **4,669 events**, including **13 events containing Python-related user-agent activity**.

The account also showed activity involving multiple Microsoft security and administration services.

### Analyst Interpretation

The baseline established that the Python activity was a small subset of a larger authentication history and should therefore be analyzed in context rather than independently.

---

## 6.2 Python Requests Authentication

The investigation identified **13 events containing Python activity**.

Observed characteristics included:

```text
User Agent:
Python Requests 2.33.0

Application:
Microsoft Cloud App Security

Activity:
OAuth2 token authentication

Result:
Successful authentication
```

The activity was correlated with the investigated Microsoft Entra account.

### Analyst Interpretation

Programmatic authentication through Python was considered an anomaly requiring investigation.

However:

> The use of Python Requests does not by itself establish malicious activity.

Python is commonly used for legitimate automation, scripts, API clients, and security tooling.

The investigation therefore continued to determine what permissions were associated with the authentication activity and whether corresponding downstream actions could be identified.

---

## 6.3 OAuth Permission Analysis

Authentication-processing telemetry associated with the Python activity contained:

```text
Application.ReadWrite.All
```

This permission was considered significant because it relates to application-management capabilities.

### Analyst Interpretation

The presence of this permission increased the investigation priority.

However, authentication telemetry showing an OAuth scope does **not** by itself establish:

- That an application was modified
- That the permission was abused
- That a malicious actor obtained the token
- That persistence was established

The permission was therefore treated as an investigation lead.

---

## 6.4 Session Correlation

The Python activity was correlated with a broader authentication session.

The session included activity associated with Microsoft security and administration services such as:

- Microsoft Cloud App Security
- Microsoft Defender Hunting
- Microsoft 365 Security and Compliance Center
- Azure Portal
- Azure Resource Manager
- WindowsDefenderATP
- Security Copilot API
- Microsoft Threat Protection
- Microsoft Exchange Online Protection

Multiple client types were also observed within the broader session, including Python Requests, Chrome, and Microsoft Rich Client activity.

### Analyst Interpretation

The session correlation demonstrated that the Python activity occurred within a broader Microsoft security/admin authentication context.

This reduced the risk of interpreting the Python events in isolation.

At the same time, the Python activity remained an anomaly because its programmatic client characteristics differed from normal interactive browser activity.

---

# 7. Downstream Activity Investigation

## 7.1 Microsoft Graph API Investigation

A follow-up query was performed against:

```text
GraphAPIAuditEvents
```

The investigation searched for matching activity involving:

```text
Application.ReadWrite.All
```

during the investigation window.

### Result

```text
No results found in the specified time frame.
```

### Interpretation

No matching Graph API audit records were returned by the query.

This finding does **not** prove that no API activity occurred.

It means that no corresponding records were available in the queried telemetry under the specified conditions.

---

## 7.2 Administrative Audit Investigation

A second follow-up investigation was performed against:

```text
AuditLogs
```

for the investigated account and time period.

### Result

```text
No results found in the specified time frame.
```

### Interpretation

No matching administrative audit records were returned.

As with the Graph API investigation, absence of telemetry is not proof that no action occurred.

The result was therefore treated as supporting evidence, not definitive proof of absence.

---

# 8. Evidence Summary

The public portfolio evidence is organized as:

```text
evidence/
├── account-baseline.png
├── python-oauth-activity.png
├── application-readwrite-scope.png
├── session-timeline.png
├── graph-api-no-results.png
└── audit-no-results.png
```

Sensitive values such as:

- Real IP addresses
- Account identifiers
- Session identifiers
- Correlation identifiers

should be redacted before public publication.

---

# 9. MITRE ATT&CK Mapping

## T1078 — Valid Accounts

The investigation involved authenticated activity using a valid Microsoft Entra account.

This mapping describes the observed use of valid authentication credentials.

**Assessment:** Applicable to observed authentication activity; unauthorized use was not established.

---

## T1528 — Steal Application Access Token

Token-related authentication and OAuth permissions were investigated as a potential token-abuse scenario.

**Assessment:** Considered during investigation; token theft was not confirmed.

---

## T1098 — Account Manipulation

Application and identity changes were investigated as a possible persistence or privilege-abuse mechanism.

**Assessment:** No corresponding administrative change was identified in the queried audit telemetry.

---

# 10. Impact Assessment

| Investigation Area | Assessment |
|---|---|
| Authentication anomaly | Observed |
| Python-based authentication | Observed |
| Microsoft Cloud App Security activity | Observed |
| `Application.ReadWrite.All` | Observed in authentication-processing data |
| Confirmed malicious activity | Not established |
| Confirmed account compromise | Not established |
| Confirmed token theft | Not established |
| Application modification | Not observed in queried telemetry |
| Persistence | Not observed in queried telemetry |
| Confirmed data exfiltration | Not established |
| Privilege abuse | Not established |

---

# 11. Timeline Summary

```text
26 Sep 2026
│
├── Interactive Microsoft security/admin authentication
│
├── Additional non-interactive OAuth2 token activity
│
└── Python Requests activity observed
       │
       ▼
28 Sep 2026
│
├── Additional security/admin authentication activity
│
├── Python Requests activity
│
├── Application.ReadWrite.All observed
│
└── Additional authentication anomalies investigated
       │
       ▼
29 Sep 2026
│
├── Further Python Requests authentication activity
│
└── Investigation continued through downstream telemetry
       │
       ▼
Graph API / Audit Investigation
│
├── No matching GraphAPIAuditEvents returned
└── No matching AuditLogs returned
```

---

# 12. Investigation Conclusion

The investigation identified anomalous programmatic authentication involving **Python Requests 2.33.0** and **Microsoft Cloud App Security**.

Authentication-processing telemetry associated with this activity contained:

```text
Application.ReadWrite.All
```

Because of the sensitivity of this permission, the investigation was expanded to examine session context and potential downstream activity.

The Python activity was found within a broader Microsoft security/admin authentication session.

Follow-up queries against Microsoft Graph API audit telemetry and administrative audit telemetry did not return matching records for the investigated conditions and time period.

Based on the available telemetry:

> **Confirmed compromise or malicious use could not be established.**

The investigation therefore remains classified as:

```text
Anomalous authentication activity
— unconfirmed maliciousness
```

The primary unresolved question is the legitimate source and purpose of the Python-based automation.

---

# 13. Recommended SOC Follow-Up

If this were a production investigation, useful follow-up actions would include:

1. Validate whether the Python automation was authorized.
2. Identify the owner and source system of the automation.
3. Review application/service-principal configuration associated with the observed activity.
4. Review additional endpoint telemetry for the source device where available.
5. Review identity-provider and conditional-access telemetry for additional context.
6. Investigate any newly created or modified application credentials if corresponding audit telemetry becomes available.
7. Continue monitoring for repeated anomalous programmatic authentication.

These actions are investigation recommendations rather than conclusions about malicious activity.

---

# 14. Investigation Limitations

The conclusions in this report are limited to the telemetry available during the documented investigation window.

Important limitations include:

- Absence of audit records does not prove that no action occurred.
- Authentication telemetry alone cannot establish user intent.
- An OAuth permission in token/authentication telemetry does not prove that the permission was abused.
- Python Requests is a legitimate software library.
- Additional endpoint, application, identity-provider, or cloud-service telemetry could provide additional context.
- The investigation did not establish the exact source or business purpose of the Python automation.

---

# 15. KQL Investigation Queries

The investigation queries are stored in the `queries/` directory:

```text
queries/
├── 01_account_baseline.kql
├── 02_python_requests.kql
├── 03_oauth_permissions.kql
├── 04_session_correlation.kql
├── 05_graph_api_investigation.kql
└── 06_audit_investigation.kql
```

The queries represent the investigation workflow from initial detection through downstream validation.

---

# 16. Analyst Skills Demonstrated

This investigation demonstrates practical experience with:

- Microsoft Defender Advanced Hunting
- Kusto Query Language (KQL)
- Microsoft Entra ID
- Identity investigation
- Authentication anomaly detection
- OAuth investigation
- Application permission analysis
- Session correlation
- Microsoft Graph audit investigation
- Entra audit log analysis
- MITRE ATT&CK mapping
- SOC incident documentation
- Evidence-based incident disposition
- Security investigation methodology

---

# 17. Public Portfolio Handling

Before publishing the project publicly, sensitive identifiers should be redacted from screenshots and documentation.

Recommended redactions:

```text
Real IP addresses       → REDACTED_IP
Account/tenant identity → REDACTED_ACCOUNT
Session IDs             → REDACTED_SESSION
Correlation IDs         → REDACTED_CORRELATION_ID
```

Application IDs and Microsoft service/application names may remain visible when they are useful for explaining the investigation and do not expose secrets.

---

## Final Disposition

```text
┌─────────────────────────────────────────────┐
│  ANOMALOUS AUTHENTICATION ACTIVITY         │
│                                             │
│  Maliciousness:        NOT CONFIRMED        │
│  Compromise:           NOT ESTABLISHED      │
│  Further investigation: RECOMMENDED        │
└─────────────────────────────────────────────┘
```
