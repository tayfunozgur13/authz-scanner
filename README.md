# AuthZ Scanner

AuthZ Scanner is a **config-driven REST API authorization security testing tool** built with Python.

The project is designed to test common authorization vulnerabilities across REST APIs and compare the behavior of intentionally vulnerable and hardened implementations.

It consists of two main components:

- A demo API laboratory containing vulnerable and hardened FastAPI applications
- A reusable authorization scanner that performs HTTP-based security tests using YAML configuration files

The primary goal is to demonstrate how the same scanner behaves against two implementations of the same API:

```text
Vulnerable API  -> authorization findings detected
Hardened API    -> no findings expected for the same test cases
```

---

## Security Coverage

AuthZ Scanner currently evaluates the following vulnerability classes:

- **BOLA** — Broken Object Level Authorization
- **BFLA** — Broken Function Level Authorization
- **Excessive Data Exposure**
- **Mass Assignment**
- **Privilege Escalation**
- **Unauthenticated Access**

These behaviors are intentionally implemented in two different demo environments:

- `apps/vulnerable_api` — intentionally insecure API used to demonstrate authorization vulnerabilities
- `apps/hardened_api` — secured implementation of the same API behavior

The scanner itself does not contain hardcoded target endpoints.

Target URLs, authentication details, user identities, object identifiers, and test rules are defined through YAML configuration files under `config/`.

---

## Architecture

```text
                    +----------------------+
                    |   Scanner Config     |
                    |    YAML Files        |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |   AuthZ Scanner      |
                    |                      |
                    |  Identity Manager    |
                    |  HTTP Executor       |
                    |  Scanner Modules     |
                    |  Evidence Handling   |
                    +----------+-----------+
                               |
               +---------------+---------------+
               |                               |
               v                               v
    +----------------------+        +----------------------+
    |   Vulnerable API     |        |    Hardened API      |
    |      FastAPI         |        |       FastAPI        |
    +----------+-----------+        +----------+-----------+
               |                               |
               v                               v
       Findings Expected                No Findings Expected
               |
               v
    +----------------------+
    | Reporting Layer      |
    | JSON / Markdown / HTML |
    +----------------------+
```

---

## Project Structure

```text
authz-scanner/
├── apps/
│   ├── vulnerable_api/
│   ├── hardened_api/
│   └── reset_demo_data.py
│
├── scanner/
│   ├── core/
│   ├── discovery/
│   ├── modules/
│   ├── reporting/
│   └── main.py
│
├── config/
│   ├── vulnerable.yaml
│   ├── hardened.yaml
│   ├── generated-from-openapi.yaml
│   └── example_external.yaml
│
├── docs/
│   └── configuration.md
│
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

### Main Components

#### `apps/`

Contains the intentionally vulnerable and hardened FastAPI demo applications.

#### `scanner/core/`

Contains reusable scanner infrastructure including:

- configuration handling
- identity management
- HTTP execution
- result models
- evidence models
- finding models

#### `scanner/modules/`

Contains individual authorization testing modules such as:

- BOLA scanner
- BFLA scanner
- property authorization scanner

#### `scanner/discovery/`

Contains helpers for creating reviewable starter scanner configuration from OpenAPI documents.

#### `scanner/reporting/`

Generates machine-readable and human-readable security reports.

#### `config/`

Defines target-specific scanner behavior.

This allows the scanner engine to remain independent from the demo API implementation.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/tayfunozgur13/authz-scanner.git
cd authz-scanner
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

### macOS / Linux

```bash
source .venv/bin/activate
```

### Windows

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The project uses a standard Python repository structure and can be opened with editors such as VS Code, Cursor, or PyCharm.

---

## Running the Demo APIs

Start the intentionally vulnerable API:

```bash
uvicorn apps.vulnerable_api.main:app --reload --port 8001
```

Start the hardened API:

```bash
uvicorn apps.hardened_api.main:app --reload --port 8002
```

Both APIs should be running when performing a comparative scan.

### Health Endpoints

```text
http://127.0.0.1:8001/health
http://127.0.0.1:8002/health
```

### OpenAPI Documents

```text
http://127.0.0.1:8001/openapi.json
http://127.0.0.1:8002/openapi.json
```

---

## Demo Identities

Demo users are automatically seeded when the APIs start.

| Identity | Email | Password | Role |
| --- | --- | --- | --- |
| userA | `userA@example.com` | `Password123!` | `customer` |
| userB | `userB@example.com` | `Password123!` | `customer` |
| support1 | `support1@example.com` | `Password123!` | `support` |
| manager1 | `manager1@example.com` | `Password123!` | `manager` |
| admin1 | `admin1@example.com` | `Password123!` | `admin` |

These credentials are used **only for the local intentionally vulnerable/hardened demo environment**.

The seed data uses fixed UUID values to keep object references consistent across scans and reports.

---

## Scanner Usage

### Scan the Vulnerable API

```bash
python -m scanner.main --config config/vulnerable.yaml
```

### Scan the Hardened API

```bash
python -m scanner.main --config config/hardened.yaml
```

### Generate JSON Report

```bash
python -m scanner.main \
  --config config/vulnerable.yaml \
  --report-format json
```

### Generate Markdown Pentest Report

```bash
python -m scanner.main \
  --config config/vulnerable.yaml \
  --report-format markdown
```

### Generate HTML Report

```bash
python -m scanner.main \
  --config config/vulnerable.yaml \
  --report-format html
```

### Generate All Report Formats

```bash
python -m scanner.main \
  --config config/vulnerable.yaml \
  --report-format all
```

### Compare Vulnerable and Hardened Targets

```bash
python -m scanner.main \
  --compare-config config/vulnerable.yaml config/hardened.yaml
```

Expected demo behavior:

```text
vulnerable: 19 findings
hardened: 0 findings
```

The exact number of findings depends on the current scanner configuration and demo implementation.

### Validate Scanner Config

Run the config doctor before a scan to catch missing identities, unresolved path placeholders, review flags, unreachable auth/profile endpoints, and resource list shape problems:

```bash
python -m scanner.main config doctor --config config/vulnerable.yaml
```

For static-only validation without connecting to the target API:

```bash
python -m scanner.main config doctor --config config/vulnerable.yaml --offline
```

The legacy flag form is also supported:

```bash
python -m scanner.main --config config/vulnerable.yaml --doctor
```

---

## OpenAPI Starter Config Generation

AuthZ Scanner can generate a starter YAML configuration from an OpenAPI document:

```bash
python -m scanner.discovery.openapi \
  --openapi http://127.0.0.1:8001/openapi.json \
  --base-url http://127.0.0.1:8001 \
  --output config/generated-from-openapi.yaml \
  --compare-with config/vulnerable.yaml
```

This feature is intended to reduce manual setup time when onboarding a new API.

It does not blindly decide final authorization rules. Generated tests include:

- `review_required: true`
- `review_notes`
- `destructive: true` for inferred mutation-capable tests and payloads
- placeholder identities such as `TODO_OWNER_EMAIL`
- inferred BOLA, BFLA, excessive data exposure, mass assignment, and privilege escalation candidates

The pentester should review and complete these fields before running the generated config against a real target.

### Starter Config Review Checklist

Before using an OpenAPI-generated starter config against a real API:

- Replace placeholder identities with authorized test accounts.
- Confirm the login endpoint and token response field.
- Confirm the profile endpoint and user identifier field.
- Confirm ownership fields used by object-level authorization tests.
- Complete request bodies for non-GET endpoints when required.
- Make mass assignment payloads valid for the target API.
- Review every `destructive: true` test before running with `--include-destructive`.
- Customize business impact statements for the application's real business context.
- Review extra generated candidates before keeping or removing them.
- Keep `review_required: true` until the test has been manually validated.

For the included vulnerable demo API, the current OpenAPI-generated starter config matches most manually defined BOLA candidates and several property authorization candidates. The remaining cross-tenant and role-workflow cases are intentionally left to human review because OpenAPI alone cannot fully infer organization isolation rules or business approval rules such as support-versus-manager permissions.

---

## How Authorization Testing Works

Authorization testing requires multiple identities and expected access-control rules.

For example, a simplified BOLA test may follow this logic:

```text
1. Authenticate as User A
2. Access User A's resource
3. Store the resource identifier
4. Authenticate as User B
5. Attempt to access User A's resource
6. Evaluate the HTTP response and returned data
7. Generate a finding if unauthorized access succeeds
```

This approach allows the scanner to evaluate actual authorization behavior rather than relying only on static endpoint definitions.

---

## BOLA Detection

BOLA tests evaluate whether one authenticated user can access objects belonging to another user or another organization.

The demo lab includes customer-owned orders, invoices, and support tickets so the scanner can test multiple resource types instead of a single simplified object model.

Example:

```text
User A -> GET /orders/USER_A_ORDER_ID -> 200 OK
User B -> GET /orders/USER_A_ORDER_ID -> 200 OK
User B -> GET /organizations/ORG_A_ID/invoices/USER_A_INVOICE_ID -> 200 OK
```

If User B receives User A's protected object without proper authorization, the scanner generates a BOLA finding.

---

## BFLA Detection

BFLA tests evaluate whether lower-privileged users can invoke privileged API functions.

The demo lab includes `customer`, `support`, `manager`, and `admin` roles. This allows the scanner to check both broad privilege boundaries, such as customer access to admin endpoints, and narrower workflow boundaries, such as a support user assigning a ticket but not closing it without manager approval.

Example:

```text
Regular User -> POST /admin/users
```

If an endpoint intended only for administrators can be successfully accessed by a normal user, the scanner records a BFLA finding.

---

## Property Authorization Testing

The property authorization module evaluates issues such as:

- Mass Assignment
- Excessive Data Exposure
- Privilege Escalation

It supports both fixed endpoints such as `/users/me` and resource detail endpoints such as `/support/tickets/{id}`, where the scanner first discovers a valid object id from a configured list endpoint.

Example privilege escalation attempt:

```json
{
  "name": "User A",
  "role": "admin"
}
```

If an ordinary user can modify a protected property such as `role`, the scanner generates a security finding.

---

## Reporting

AuthZ Scanner supports three report formats.

### JSON

Designed for automated processing and integrations.

Possible future uses include:

- CI/CD pipelines
- security dashboards
- vulnerability management systems
- automated post-processing

### Markdown

Designed as a human-readable penetration testing report.

### HTML

Designed as a browser-readable report for demos and easier review.

The Markdown and HTML reports include:

- Executive Summary
- Scan Metadata
- Tested Identities
- Findings Summary
- Detailed Findings
- Evidence Appendix
- cURL reproduction commands

Each finding can contain:

- Severity
- Risk score
- Vulnerability class
- OWASP API category
- Affected endpoint
- Impact
- Business impact
- Steps to reproduce
- cURL reproduction
- Evidence summary
- Remediation guidance

Business impact can be defined in scanner configuration for each test or payload.
This keeps the scanner reusable across APIs while allowing the report to explain the real business risk of each endpoint.

cURL reproduction commands use placeholder authentication values such as:

```text
Authorization: Bearer <userA_token>
```

Request bodies are redacted before being written into cURL examples, so sensitive fields such as passwords and tokens are not leaked into generated reports.

---

## Severity and Risk Scoring

Scanner findings include both a severity label and a numeric risk score:

```text
low       -> 20
medium    -> 50
high      -> 80
critical  -> 95
```

The scanner can infer severity from vulnerability class, HTTP method, and endpoint context.

Examples:

- privilege escalation defaults to `critical`
- unauthorized refund, approval, or admin actions default to `critical`
- mutating BOLA requests such as `PUT` or `DELETE` default to `critical`
- read-only customer data access usually defaults to `high`
- lower-impact data exposure may default to `medium`

For stronger pentest reporting, YAML config can explicitly override both values:

```yaml
bfla:
  tests:
    - name: users_cannot_refund_orders
      role: customer
      attack:
        method: POST
        path_template: /orders/{id}/refund
      expected_status: 403
      severity: critical
      risk_score: 98
```

Payload-level overrides are also supported for property authorization tests, which lets different mass assignment payloads carry different risk scores.

---

## Destructive Test Guard

Some authorization checks are safe read-only probes. Others intentionally try to change target state.

Examples of destructive tests:

- updating or cancelling another user's order
- calling refund or approval actions
- assigning or closing support tickets
- submitting mass assignment payloads that create or modify records
- attempting role promotion through profile update endpoints

These tests are marked in YAML:

```yaml
destructive: true
reset_recommended: true
```

By default, destructive tests are skipped:

```bash
python -m scanner.main --config config/vulnerable.yaml
```

The CLI and reports show which tests were skipped.

Run the full mutation-capable scan only when the target environment can tolerate state changes:

```bash
python -m scanner.main \
  --compare-config config/vulnerable.yaml config/hardened.yaml \
  --include-destructive \
  --report-format all
```

`reset_recommended: true` means the test may leave demo data changed after execution.

The scanner does not automatically reset target data. Reset is a separate environment operation so that real external APIs are never modified by hidden scanner side effects.

---

## Sensitive Data Redaction

The reporting layer automatically masks sensitive values.

Examples include:

```text
password
password_hash
token
refresh_token
api_key
secret
ssn
card information
```

Sensitive values are replaced with:

```text
[REDACTED]
```

This reduces the risk of exposing credentials or sensitive application data inside generated reports.

---

## Report Management

Generated reports are stored locally under:

```text
reports/
```

The directory is intended for local scan output and is not committed to the repository.

Each reporting run updates:

```text
reports/manifest.json
```

Convenience files are also generated:

```text
reports/latest.json
reports/latest.md
reports/latest.html
```

These provide quick access to the most recent scan results.

---

## Resetting Demo Data

Some scanner modules intentionally perform mutation-based authorization tests.

For example:

- a privilege escalation test may temporarily change `userA` from `customer` to `admin`
- a mass assignment test may create or modify an object
- authorization tests may modify application state
- support workflow tests may assign or close demo support tickets

Reset the demo environment with:

```bash
python -m apps.reset_demo_data
```

Expected output:

```text
Reset demo data for: vulnerable, hardened
```

The reset operation belongs to the demo API environment rather than the scanner itself.

The scanner performs tests but does not automatically manage target application state outside explicitly defined test actions.

---

## Error Handling

Common runtime failures are converted into concise CLI messages instead of exposing unnecessary tracebacks.

Examples include:

```text
Scanner error: Config file not found
Scanner error: Config file is invalid
Authentication error
Connection error
```

For these execution failures, the scanner exits with:

```text
exit code 2
```

---

## Testing

Run the complete test suite with:

```bash
python -m pytest
```

The test suite covers:

- API health checks
- OpenAPI availability
- Login behavior
- JWT authentication
- Order endpoints
- Invoice endpoints
- Support ticket endpoints
- User endpoints
- Admin endpoints
- BOLA scanner module
- BFLA scanner module
- Property authorization scanner
- JSON reporting
- Markdown reporting
- HTML reporting
- CLI error handling
- Comparative scanning
- Demo database reset behavior

---

## CI/CD

The repository includes a **GitHub Actions** pipeline.

Tests are automatically executed on:

```text
push
pull_request
```

This allows scanner functionality to be continuously validated as the project evolves.

The CI pipeline represents the first step toward integrating authorization security testing into a broader DevSecOps workflow.

---

## Portability

AuthZ Scanner is intentionally designed so that the scanner engine is not tightly coupled to the included demo APIs.

Testing another REST API primarily requires a new configuration file containing information such as:

- target base URL
- authentication endpoint
- authentication request
- token extraction path
- authentication header format
- profile endpoint
- test identities
- BOLA rules
- BFLA rules
- property authorization rules
- business impact statements for important tests or payloads

OpenAPI starter generation can create the first draft of this file, but final authorization decisions still need human review.

Authorization logic is highly dependent on application-specific business rules.

For this reason, the scanner does not attempt to fully infer authorization expectations automatically.

Instead, expected behavior is defined explicitly through configuration files.

The same rule applies to business impact. The scanner includes generic fallback impact text, but a stronger pentest report should define API-specific business impact in YAML.

For additional details, see:

```text
docs/configuration.md
```

A starter configuration is available at:

```text
config/example_external.yaml
```

---

## Example External Configuration

A simplified configuration may look conceptually like this:

```yaml
target:
  base_url: "http://localhost:8000"

auth:
  login_path: "/login"
  login_method: "POST"
  credential_location: "header"
  token_field: "access_token"
  token_path: "data.access_token"
  auth_header_name: "Authorization"
  auth_scheme: "Bearer"
  login_body:
    username: "{email}"
    password: "{password}"

identities:
  user_a:
    email: "userA@example.com"
    password: "password"
    role: "user"

  user_b:
    email: "userB@example.com"
    password: "password"
    role: "user"
```

Target-specific authorization rules can then be defined without changing the scanner engine.

For cookie/session based APIs, use:

```yaml
auth:
  login_path: "/session"
  token_field: "token"
  credential_location: "cookie"
  cookie_name: "session_id"
```

The demo APIs also include cookie-auth scanner configs:

```bash
python -m scanner.main --compare-config config/vulnerable_cookie.yaml config/hardened_cookie.yaml
```

For APIs that issue refresh tokens, configure the refresh endpoint:

```yaml
auth:
  login_path: "/session"
  token_field: "access_token"
  refresh_path: "/session/refresh"
  refresh_token_field: "refresh_token"
  refresh_on_status_codes: [401]
  refresh_body:
    refresh_token: "{refresh_token}"
```

When a configured request receives `401`, the scanner refreshes that identity's access token and retries the same request once.

The demo APIs include refresh-token scanner configs that intentionally start with expired access tokens:

```bash
python -m scanner.main --compare-config config/vulnerable_refresh.yaml config/hardened_refresh.yaml
```

---

## Security and Ethical Use

AuthZ Scanner is intended for:

- local security labs
- intentionally vulnerable applications
- systems owned by the tester
- systems where explicit authorization for security testing has been granted

Do not use the scanner against systems without permission.

The included vulnerable API exists specifically to provide a controlled environment for security testing and development.

---

## Current Limitations

The project currently has several intentional limitations:

- Authorization expectations must largely be defined manually through configuration.
- The scanner does not automatically discover complete business authorization rules.
- Business impact quality depends on the API-specific context provided in configuration.
- OpenAPI starter generation is heuristic and requires review before real-world use.
- The included vulnerability modules focus primarily on authorization-related API security issues.
- Some mutation-based tests can modify target application state.
- The demo environment is designed for controlled security testing rather than production deployment.

---

## Future Work

Planned improvements include:

- More advanced OpenAPI-based configuration discovery
- Better schema analysis for required request body fields
- Docker support for the scanner and demo APIs
- Improved CI/CD security integration
- Additional API authorization test modules
- More advanced evidence correlation
- Enhanced comparison between vulnerable and remediated API versions

---

## Project Goals

AuthZ Scanner was developed to explore the intersection of:

- Backend Engineering
- API Security
- Application Security
- Security Automation
- Software Testing
- DevSecOps

The project demonstrates how authorization security tests can be represented as reusable, repeatable, and reportable automated workflows rather than only manual penetration testing steps.

---

## Developer

**Tayfun Özgür**

GitHub: [tayfunozgur13](https://github.com/tayfunozgur13)
