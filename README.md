# Microsoft Defender L3 SOC Investigation — OAuth & Programmatic Authentication

## Overview

A hands-on SOC investigation using Microsoft Defender Advanced Hunting to investigate anomalous programmatic authentication involving Python Requests, Microsoft Cloud App Security, OAuth permissions, and session activity.

The project is structured around a **SOC investigation lifecycle (L1 → L2 → L3)**, with the primary hands-on focus on the **L3 deep investigation stage**.

> **Investigation outcome:** Anomalous authentication activity was identified, but confirmed malicious use or compromise could not be established from the available telemetry.

---

## Investigation Scenario

During monitoring of Microsoft Entra sign-in telemetry, unusual programmatic authentication activity was identified for an investigated administrative account.

The investigation examined:

- Initial authentication anomaly
- Python Requests authentication
- Microsoft Cloud App Security activity
- OAuth permissions
- Session correlation
- Microsoft Graph API activity
- Administrative audit activity
- Final incident disposition

The objective was to determine whether the observed activity showed evidence of unauthorized access, OAuth token abuse, application modification, persistence, privilege abuse, or confirmed account compromise.

---

## SOC Workflow Coverage

This project demonstrates how the investigation fits into a broader SOC workflow:

```text
┌──────────────────────┐
│ L1 — Detection/Triage│
│                      │
│ • Identify anomaly   │
│ • Validate account   │
│ • Establish timeframe│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ L2 — Analysis        │
│                      │
│ • Authentication    │
│ • Client analysis   │
│ • Session correlation│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ L3 — Deep            │
│ Investigation        │
│                      │
│ • OAuth analysis     │
│ • Graph investigation│
│ • Audit investigation│
│ • MITRE mapping      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Reporting &          │
│ Disposition          │
│                      │
│ • Impact assessment  │
│ • Evidence           │
│ • Final conclusion   │
└──────────────────────┘
```

### Project focus

The project is **not presented as a complete L1/L2/L3 SOC implementation**. The primary hands-on work is the **L3 investigation**, supported by the earlier triage and correlation stages.

---

## Environment

| Component | Technology |
|---|---|
| Investigation Platform | Microsoft Defender XDR |
| Query Language | Kusto Query Language (KQL) |
| Identity Telemetry | Microsoft Entra sign-in events |
| API Telemetry | Graph API Audit Events |
| Audit Telemetry | Microsoft Entra Audit Logs |
| Investigation Type | L3 SOC / Identity Security Investigation |

---

## Investigation Methodology

```text
L1 — Initial Triage
        ↓
Account Baseline
        ↓
Identify Python-Based Authentication
        ↓
L2 — Authentication & Session Analysis
        ↓
Correlate Applications / Clients / Session
        ↓
L3 — Deep Investigation
        ↓
Analyze OAuth Permissions
        ↓
Investigate Graph API Activity
        ↓
Investigate Administrative Audit Activity
        ↓
Impact Assessment
        ↓
Final Disposition
```

---

## Key Findings

### 1. Account Baseline — L1 Triage

The account baseline query returned:

- **4,669 total events** in the current investigation query
- **13 events containing Python-related user-agent activity**

The account showed activity across multiple Microsoft security and administration services.

The baseline established the timeframe and volume required for deeper investigation.

---

### 2. Python Requests Activity — L1/L2 Analysis

The investigation identified **13 authentication events containing Python activity**.

Observed characteristics included:

- `Python Requests 2.33.0`
- Microsoft Cloud App Security
- OAuth2 token activity
- Successful authentication
- Activity associated with the investigated account

Python-based authentication was treated as an anomaly requiring investigation.

The presence of Python Requests alone was **not considered proof of malicious activity**.

---

### 3. OAuth Permission Analysis — L3 Investigation

Authentication-processing data associated with the Python activity contained:

```text
Application.ReadWrite.All
```

This permission relates to application-management capabilities and therefore warranted deeper investigation.

The presence of `Application.ReadWrite.All` in authentication/token telemetry does **not by itself demonstrate that an application was modified or that the permission was maliciously abused**.

---

### 4. Session Correlation — L2/L3 Analysis

The Python activity was correlated with a broader authentication session.

The session included activity involving multiple Microsoft security and administration services, including:

- Microsoft Cloud App Security
- Microsoft Defender Hunting
- Microsoft 365 Security and Compliance Center
- Azure Portal
- Azure Resource Manager
- WindowsDefenderATP
- Security Copilot API
- Microsoft Threat Protection
- Microsoft Exchange Online Protection

This correlation helped establish that the Python activity occurred within a broader Microsoft security/admin authentication context rather than appearing as an isolated event.

---

### 5. Microsoft Graph API Investigation — L3

A follow-up investigation was performed against:

```text
GraphAPIAuditEvents
```

The query searched the investigation window for activity associated with:

```text
Application.ReadWrite.All
```

**Result:**

```text
No results found in the specified time frame.
```

This means no matching Graph API audit records were returned by the query.

It does **not** prove that no API activity occurred; it establishes only that no corresponding records were available under the queried conditions.

---

### 6. Administrative Audit Investigation — L3

A follow-up query was performed against:

```text
AuditLogs
```

for the investigated account and time period.

**Result:**

```text
No results found in the specified time frame.
```

No matching administrative audit records were returned by the query.

The absence of records is treated as a telemetry limitation rather than proof that no action occurred.

---

## Evidence

The investigation evidence is organized as follows:

```text
evidence/
├── account-baseline.png
├── python-oauth-activity.png
├── application-readwrite-scope.png
├── session-timeline.png
├── graph-api-no-results.png
└── audit-no-results.png
```

Sensitive information such as real IP addresses, account identifiers, and session identifiers should be redacted before publishing screenshots publicly.

---

## MITRE ATT&CK Mapping

### T1078 — Valid Accounts

The investigation involved authenticated activity using a valid Microsoft Entra account.

This mapping describes the observed use of valid authentication credentials; unauthorized use was **not established**.

### T1528 — Steal Application Access Token

Token-related activity and OAuth permissions were investigated as a potential token-abuse scenario.

Token theft itself was **not confirmed**.

### T1098 — Account Manipulation

Application and identity changes were investigated as a potential persistence or privilege-abuse mechanism.

No corresponding administrative change was identified in the queried audit telemetry.

---

## Impact Assessment

| Area | Assessment |
|---|---|
| Initial authentication anomaly | **Observed** |
| Python-based authentication | **Observed** |
| `Application.ReadWrite.All` in authentication data | **Observed** |
| Confirmed malicious activity | **Not established** |
| Confirmed account compromise | **Not established** |
| Confirmed token theft | **Not established** |
| Application modification | **Not observed in queried telemetry** |
| Persistence | **Not observed in queried telemetry** |
| Confirmed data exfiltration | **Not established** |
| Privilege abuse | **Not established** |

---

## Investigation Conclusion

### Disposition

**Anomalous authentication activity — unconfirmed maliciousness**

The investigation identified unusual programmatic authentication involving Python Requests and Microsoft Cloud App Security. Authentication-processing data showed `Application.ReadWrite.All` in the observed token activity.

Additional investigation did not return matching Graph API audit records or administrative AuditLogs records for the queried conditions and investigation window.

Based on the available telemetry, **confirmed compromise or malicious use could not be established**.

The primary outstanding investigation question is the legitimate source and purpose of the Python-based automation.

---

## Investigation Limitations

This investigation was limited to the telemetry available during the documented investigation window.

Important limitations include:

- Absence of audit records does not prove that no action occurred.
- Authentication telemetry alone cannot establish user intent.
- The presence of an OAuth permission does not prove that the permission was abused.
- Python Requests is a legitimate automation library and is not inherently malicious.
- Additional endpoint, application, identity-provider, or cloud-service telemetry could provide further context.
- The exact source and business purpose of the Python automation were not established.

---

## KQL Queries

The investigation queries are stored separately for reproducibility:

```text
queries/
├── 01_account_baseline.kql
├── 02_python_requests.kql
├── 03_oauth_permissions.kql
├── 04_session_correlation.kql
├── 05_graph_api_investigation.kql
└── 06_audit_investigation.kql
```

The queries correspond to the investigation stages from baseline triage through L3 validation.

---

## Skills Demonstrated

### L1 / Triage

- Authentication baseline analysis
- Alert/anomaly validation
- Timeframe analysis
- Account activity profiling

### L2 / Analysis

- Authentication event analysis
- Client/user-agent analysis
- Application correlation
- Session correlation
- Microsoft security service correlation

### L3 / Deep Investigation

- Advanced KQL investigation
- OAuth permission analysis
- `Application.ReadWrite.All` investigation
- Microsoft Graph audit investigation
- Entra AuditLogs investigation
- MITRE ATT&CK mapping
- Evidence-based incident disposition

### Reporting

- SOC investigation documentation
- Evidence handling
- Impact assessment
- Investigation limitations
- Final incident disposition

---

## Project Structure

```text
microsoft-defender-l3-oauth-investigation/
│
├── README.md
│
├── queries/
│   ├── 01_account_baseline.kql
│   ├── 02_python_requests.kql
│   ├── 03_oauth_permissions.kql
│   ├── 04_session_correlation.kql
│   ├── 05_graph_api_investigation.kql
│   └── 06_audit_investigation.kql
│
├── evidence/
│   ├── account-baseline.png
│   ├── python-oauth-activity.png
│   ├── application-readwrite-scope.png
│   ├── session-timeline.png
│   ├── graph-api-no-results.png
│   └── audit-no-results.png
│
└── report/
    └── SOC-Incident-Investigation.md
```

---

## Disclaimer

This project is a cybersecurity investigation lab/portfolio project using controlled telemetry.

Sensitive identifiers should be redacted before public publication.

The investigation conclusions are based only on the telemetry available during the documented investigation window.
