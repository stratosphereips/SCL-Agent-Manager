"""OWASP API Security Top 10 (2023) catalog for the Coder56 pentest console.

Single source of truth for the "one run per OWASP API Security Top 10 category"
engagement model surfaced in the standalone Coder56 console
(GET /api/coder56/api-security/catalog) and consumed by the engagement API-plan
drafting endpoint when ``EngagementMode.API`` is selected. Mirrors
services/owasp_catalog.py and services/mitre_catalog.py.

Each category carries a templated objective (``objective_template``, ``{target}`` is
the authorized engagement scope), a WSTG-style ``checklist`` of concrete sub-tests,
recommended ``tools``, ``scope_notes`` for the guardrail, and an ``assessable`` flag.

The 2023 categories are framed against the concrete coverage gaps exposed by the
OpenHospital ``de1e6112`` API pentest run (OPENHOSPITAL_DE1E6112_REMEDIATION_PLAN.md
Section 1.4): BOLA across EVERY resource id (not just /users); JWT alg-confusion and
logout/rotation failures; the mass-assignment, resource-consumption, BFLA-on-writes
and sensitive-business-flow classes that were never tested; SSRF; CORS/Swagger
misconfiguration; stale-endpoint inventory; and unsafe consumption of third-party
APIs.

``assessable`` honors the assessment caveat: API10 (Unsafe Consumption of APIs) is a
white-box / design / third-party-contract concern that a black-box runner cannot
meaningfully assess in an isolated range — it is still drafted (so coverage is
honest) but flagged ``white-box-only`` so the operator routes it to a source/design
review rather than silently producing an empty run. The remaining API categories are
``black-box`` testable against an authorized target.

Curated for an AUTHORIZED, isolated cyber-range lab. Representative commands and
tools are intentional — coder56 is a sanctioned red-team simulation subsystem.
"""
from __future__ import annotations

from typing import Any, Dict, List

# OWASP API Security Top 10 (2023). Each entry:
#   {id, name, summary, objective_template, checklist, tools, scope_notes,
#    assessable}
# `assessable`: "black-box" (the runner can test it remotely) or
#               "white-box-only" (design/source/contract concern; draft for
#               coverage but route to a review module).
API_SECURITY_CATEGORIES: List[Dict[str, Any]] = [
    {
        "id": "API1",
        "name": "Broken Object Level Authorization (BOLA)",
        "summary": "Object-level access control is missing or ineffective on API endpoints — an authenticated user can read/modify/delete ANY resource by manipulating its object identifier, not just the resources they own.",
        "objective_template": (
            "Assess {target} for Broken Object Level Authorization (OWASP API1:2023 "
            "BOLA). Enumerate EVERY object-bearing API resource id (not just "
            "/users — patients, lab results, prescriptions, vaccine records, "
            "appointments, documents), then test cross-role read/write/delete of "
            "resource ids you do not own using >=2 OWNED principals from DISTINCT "
            "role groups. Demonstrate impact with a proof-of-access to another "
            "principal's (or another tenant's) object, captured as a server "
            "response. BOLA is the #1 API risk for clinical/EHR systems — lead "
            "with it."
        ),
        "checklist": [
            "Enumerate every endpoint that takes an object identifier in path/query/body/parameter (patient_id, lab_id, prescription_id, vaccine_id, document_id).",
            "With principal A's token, request principal B's object by id (BOLA read); capture the 200 + body as proof.",
            "Cross-role write BOLA: with a low-priv token, PUT/PATCH/POST/DELETE an object id owned by a higher-priv or different-group principal.",
            "Test BOTH horizontal (same role, different tenant) and vertical (low role -> admin object) object access.",
            "Check ID predictability / enumeration (sequential ids) as an accelerant, but authorization is the defect regardless of id entropy.",
            "Capture one read and one write cross-role proof per high-value object family; record method+path+role for the coverage matrix.",
        ],
        "tools": ["burpsuite", "ffuf", "autorize", "curl", "jwt_tool"],
        "scope_notes": "IN scope: BOLA testing ONLY against {target} using OWNED principals and the object ids the engagement provisions. OUT of scope: accessing real patient/clinical data beyond a bounded proof, brute-forcing credentials, or touching hosts outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API2",
        "name": "Broken Authentication",
        "summary": "Authentication mechanisms are flawed — token alg-confusion, weak/leaked credentials, missing or bypassable MFA, predictable tokens, non-rotated/non-invalidated credentials, injection into auth flows.",
        "objective_template": (
            "Assess {target} for Broken Authentication (OWASP API2:2023). Evaluate "
            "the authentication and token lifecycle: credential policy and "
            "stuffing exposure, MFA presence and bypass, token signature/integrity "
            "(JWT alg-confusion, alg:none acceptance, key confusion), session/token "
            "rotation and invalidation on logout/password-change/privilege-change, "
            "and token predictability. Use ONLY accounts you own; do not perform "
            "mass online password attacks. A crypto/auth CLAIM requires a "
            "demonstrated primitive (a forged-and-ACCEPTED token, a recovered "
            "secret, or a captured differential) — a tool merely NAMING the "
            "vector is a hypothesis, not a finding."
        ),
        "checklist": [
            "Inspect token type/format (JWT alg/kid/claims, opaque session, OAuth bearer); fingerprint the signature scheme.",
            "JWT integrity: test alg:none / alg-confusion (RS<->HS) / key confusion / weak HMAC secret — CONFIRM only with a forged token the server ACCEPTS (a real 200).",
            "Test logout / password-change / privilege-change invalidation: does the OLD token still work after logout? (a stateless-JWT logout finding).",
            "Check token rotation: are fresh tokens issued on sensitive state changes, or is a long-lived token reused?",
            "Assess MFA presence and bounded bypass on OTP/reset codes; check auth-state predictability.",
            "Report credential-stuffing exposure (no rate limit / no lockout) — do not mass-test online.",
        ],
        "tools": ["jwt_tool", "burpsuite", "ffuf", "curl"],
        "scope_notes": "IN scope: auth/token testing ONLY against {target} with accounts you own and bounded attempts. OUT of scope: online password brute-force / credential stuffing at scale, account-lockout DoS, or attacking other users' accounts.",
        "assessable": "black-box",
    },
    {
        "id": "API3",
        "name": "Broken Object Property Level Authorization",
        "summary": "Object-property access control is missing — endpoints expose or accept properties the user should not read (over-exposure) or write (mass assignment) by appending fields like role, is_admin, userGroup, price, balance to request bodies.",
        "objective_template": (
            "Assess {target} for Broken Object Property Level Authorization (OWASP "
            "API3:2023), the MASS-ASSIGNMENT class that de1e6112 NEVER tested. For "
            "every write endpoint (POST/PUT/PATCH) on objects with a privilege or "
            "business-critical property, append privilege-escalating and "
            "business-value fields to the request body (role, is_admin, isAdmin, "
            "userGroup, group, permissions, price, balance, status, verified) and "
            "observe whether the server honors them. Cross-check responses for "
            "over-exposure (sensitive fields returned that the role should not "
            "see). Confirm with a captured differential — the server persisting a "
            "client-supplied role/escalation field is the proof."
        ),
        "checklist": [
            "Inventory write endpoints (POST/PUT/PATCH) on objects carrying role/privilege/business fields (/users, /accounts, /orders, /patients, /prescriptions).",
            "Mass assignment: append role/is_admin/userGroup/permissions to a normal write body from a low-priv token; verify the server persisted the escalation (re-read the object).",
            "Business-value mass assignment: append price/balance/discount/status/verified fields; capture the persisted change.",
            "Over-exposure (read side): diff the response fields a low-priv token sees vs what the schema/role implies; flag sensitive fields (salary, SSN, diagnosis) leaked.",
            "Cross-role: run the mass-assignment probes from >=2 principals in DISTINCT role groups.",
            "Record each confirmed mass-assignment with method+path+field+role for the coverage matrix; a write method never probed for mass-assignment is a coverage gap.",
        ],
        "tools": ["burpsuite", "ffuf", "curl", "jwt_tool"],
        "scope_notes": "IN scope: mass-assignment / property-authorization testing ONLY against {target} with accounts you own and reversible property changes. OUT of scope: permanently corrupting real clinical records, escalating to a real external account, or touching hosts outside scope.",
        "assessable": "black-box",
    },
    {
        "id": "API4",
        "name": "Unrestricted Resource Consumption",
        "summary": "APIs consume resources (CPU, memory, bandwidth, storage, third-party spend) without bounds — missing rate limits, large payloads, deep nesting, concurrent-request floods, max-int/-string coercion, zip bombs.",
        "objective_template": (
            "Assess {target} for Unrestricted Resource Consumption (OWASP "
            "API4:2023), the resource-exhaustion class de1e6112 NEVER tested. For "
            "each endpoint, probe whether resource use is bounded: missing "
            "per-client rate limits, large payload / long-string / deep-nesting "
            "handling, expensive query parameters (page-size / expansion / "
            "recursive fetch), concurrent-request behavior, and max-int / "
            "-string coercion. Demonstrate with a BOUNDED, non-destructive "
            "proof (a measurable latency or a documented missing limit) — do "
            "NOT take the service down. Missing limits are the finding, not an "
            "actual outage."
        ),
        "checklist": [
            "Probe rate limiting: send a bounded burst of identical requests; report whether a per-client limit triggers (report absence, do not flood to DoS).",
            "Large-payload / long-string / deep-nesting POST bodies and JSON; observe memory/time growth without crashing the service.",
            "Expensive query parameters: page_size=99999999, include=*, expand=deep, unbounded pagination; capture the measurable cost.",
            "Concurrent-request behavior on stateful endpoints (bounded parallelism — do not DoS).",
            "Max-int / negative / huge-number coercion on numeric fields (pagination, counts) that forces heavy processing.",
            "Document each missing bound as the finding with a minimal observable cost; no destructive exhaustion.",
        ],
        "tools": ["burpsuite", "turbo-intruder", "ffuf", "curl"],
        "scope_notes": "IN scope: resource-consumption probing ONLY against {target} with bounded, non-destructive payloads. OUT of scope: actual denial of service, taking the service offline, or flooding hosts outside scope.",
        "assessable": "black-box",
    },
    {
        "id": "API5",
        "name": "Broken Function Level Authorization (BFLA)",
        "summary": "Function-level access control is missing — administrative or privileged functions/endpoints are reachable by a lower-privilege user; the gap is especially severe on WRITE/DELETE functions (PUT/POST/PATCH/DELETE).",
        "objective_template": (
            "Assess {target} for Broken Function Level Authorization (OWASP "
            "API5:2023 BFLA), with EXPLICIT cross-role WRITE coverage — de1e6112 "
            "sent ZERO PUT/DELETE/PATCH cross-role. Enumerate every administrative "
            "and privileged function (including write/delete endpoints), then "
            "invoke each from a low-privilege token: can a non-admin create, "
            "modify, or DELETE resources they should only read? Lead with the "
            "integrity-critical write/delete surface (can a low role forge/delete "
            "a prescription, lab result, or vaccine record?). Confirm with a "
            "captured response showing the privileged function executed."
        ),
        "checklist": [
            "Enumerate administrative / privileged function endpoints (admin consoles, user-management, record create/update/delete, config).",
            "Cross-role WRITE matrix: with a low-priv token, attempt POST/PUT/PATCH/DELETE on every high-value write endpoint; capture the server's response.",
            "Cross-role DELETE: can a non-admin DELETE a prescription / lab result / vaccine record / user? (highest clinical-integrity impact).",
            "Vertical escalation: invoke admin-only functions from the lowest-priv role.",
            "Run the BFLA matrix from >=2 principals in DISTINCT role groups; cover every write method per group.",
            "Record each BFLA hit with method+path+role; a write method never exercised cross-role is a coverage gap, not a clean result.",
        ],
        "tools": ["burpsuite", "autorize", "ffuf", "curl"],
        "scope_notes": "IN scope: BFLA testing ONLY against {target} with OWNED principals and reversible actions. OUT of scope: permanently destroying real clinical records, mass deletion, or touching hosts outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API6",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "summary": "Business workflows lack protection against harmful automated or out-of-order use — reservation/checkout/transfer/redemption flows that can be abused at scale or sequenced out-of-order to cause business harm (overbooking, fraud, stock drain).",
        "objective_template": (
            "Assess {target} for Unrestricted Access to Sensitive Business Flows "
            "(OWASP API6:2023), the business-logic class de1e6112 NAMED then "
            "IGNORED. Identify the sensitive business workflows (prescription "
            "issue/cancel, lab order, vaccine administration, appointment booking, "
            "transfer, refund, redemption, registration) and probe whether they "
            "are protected against harmful automation and out-of-order execution: "
            "missing rate limits / anti-automation on the flow, replayed or "
            "skipped steps, parameter tampering that violates business rules, and "
            "race conditions that double-spend or over-consume. Confirm with a "
            "minimal, REVERSIBLE proof of the business rule violation."
        ),
        "checklist": [
            "Map sensitive multi-step business workflows (prescription/lab/vaccine/appointment/transfer/refund/redemption).",
            "Test skipping/reordering/replaying steps; tamper workflow state parameters against the business rule.",
            "Check anti-automation / rate limits on the flow (report absence; do not run destructive floods).",
            "Race conditions on one-time / quota / stock actions (bounded parallelism; capture a double-spend or over-consume).",
            "Out-of-order or duplicated finalization (submit/confirm/cancel in illegal sequences).",
            "Document each business-rule violation with a reversible proof; clinical-record harm must stay reversible.",
        ],
        "tools": ["burpsuite", "turbo-intruder", "ffuf", "curl"],
        "scope_notes": "IN scope: business-flow abuse testing ONLY against {target} with reversible, non-destructive actions. OUT of scope: real fraudulent transfer/redemption to live accounts, destructive flooding, or actions outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API7",
        "name": "Server Side Request Forgery (SSRF)",
        "summary": "The API fetches a remote resource without validating the user-supplied URL — internal port/scan, cloud-metadata access, or protocol smuggling from the server's vantage point.",
        "objective_template": (
            "Assess {target} for Server Side Request Forgery (OWASP API7:2023). "
            "Locate API inputs where the server fetches a URL you control "
            "(webhooks, importers, image/avatar/link/PDF fetchers, SSO/OAuth "
            "callbacks, render endpoints) and test for SSRF: reaching internal "
            "services/ports and loopback from the server's vantage point, cloud "
            "metadata endpoints, and URL-parser bypasses. Demonstrate with a "
            "benign callback to a host you own or a non-sensitive metadata read — "
            "no destructive internal actions."
        ),
        "checklist": [
            "Enumerate URL-fetch inputs (webhooks, avatar/import/link/image/PDF preview, SSO/OAuth callbacks, render/export).",
            "Point each at an out-of-band listener you own to confirm the server-side fetch.",
            "Test reaching internal IPs/ports and loopback (127.0.0.1, internal ranges) from the server's vantage point.",
            "Attempt cloud metadata endpoints (169.254.169.254) where the platform applies.",
            "Try URL-parser bypasses (@, #[], DNS rebinding, alternate schemes, IPv6) — bounded.",
            "Demonstrate impact with a benign callback/metadata read; do not pivot destructively.",
        ],
        "tools": ["burpsuite", "ffuf", "gopherus", "curl"],
        "scope_notes": "IN scope: SSRF testing ONLY against {target}, via callbacks to hosts you own and reads of non-sensitive metadata. OUT of scope: exfiltrating credentials to external systems, destructive internal actions, or pivoting beyond the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API8",
        "name": "Security Misconfiguration",
        "summary": "Default/unpatched or misconfigured API settings — verbose errors, unnecessary HTTP methods, permissive CORS, exposed Swagger/OpenAPI/Admin interfaces, missing security headers, stale default content.",
        "objective_template": (
            "Assess {target} for Security Misconfiguration (OWASP API8:2023). "
            "Audit the API's configuration surface: exposed Swagger/OpenAPI "
            "documentation and admin interfaces, permissive CORS reflection, "
            "unnecessary HTTP methods, verbose/stack-trace error responses, "
            "missing security headers, default/factory credentials, and stale "
            "default content. Treat an exposed interactive API documentation "
            "console (Swagger UI with 'Try it out') and a stale secondary service "
            "(e.g. an old Tomcat on :8080 left running) as findings, not "
            "background."
        ),
        "checklist": [
            "Discover exposed API documentation (Swagger/OpenAPI at /v3/api-docs, /swagger, /openapi.json, /api-docs); flag an interactive 'Try it out' console.",
            "Probe for admin / management interfaces (/, /admin, /actuator, /console, /manager).",
            "CORS audit: test reflected/credentialled CORS (Access-Control-Allow-Origin: * with Allow-Credentials: true).",
            "Trigger verbose errors / stack traces to fingerprint frameworks and versions; note missing security headers.",
            "Check unnecessary HTTP methods (PUT/DELETE/TRACE/OPTIONS), default/factory credentials.",
            "Inventory stale/default services and content (old app-server ports, default install pages) as concrete findings.",
        ],
        "tools": ["nuclei", "ffuf", "nmap", "curl", "nikto"],
        "scope_notes": "IN scope: misconfiguration discovery ONLY on {target}. OUT of scope: exploiting to pivot/destroy, brute-forcing credentials at scale, or touching hosts outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API9",
        "name": "Improper Inventory Management",
        "summary": "Stale, exposed, or undocumented API hosts/versions/endpoints — old API versions left reachable, shadow APIs, deprecated hosts (e.g. a stale Tomcat on :8080), broken access control on older versions.",
        "objective_template": (
            "Assess {target} for Improper Inventory Management (OWASP API9:2023). "
            "Inventory the FULL API surface — including stale and deprecated "
            "hosts, old API versions (/v1 alongside /v2), shadow/undocumented "
            "endpoints, and exposed staging/legacy services. Frame a reachable "
            "stale host (e.g. an old Tomcat left on :8080) as a CONCRETE finding, "
            "not background noise. Older API versions frequently retain "
            "vulnerabilities patched in the current version and missing on the "
            "new auth surface — re-test BOLA/BFLA/mass-assignment against any "
            "stale version you discover."
        ),
        "checklist": [
            "Inventory all API hosts/ports/versions (current + staging + legacy); flag reachable stale services (old Tomcat/app-server ports).",
            "Enumerate old API versions (/v1, /v2) and shadow/undocumented endpoints alongside the documented surface.",
            "Re-run BOLA/BFLA/mass-assignment checks against old versions — fixes often live only on the current version.",
            "Check whether deprecated endpoints retain authentication/authorization at all (often dropped on legacy).",
            "Diff old vs current auth surface (token formats, scopes, required headers).",
            "Record each stale host/version as a finding with the exposure and the re-test result.",
        ],
        "tools": ["nmap", "ffuf", "nuclei", "curl", "burpsuite"],
        "scope_notes": "IN scope: API inventory + re-testing ONLY against {target} and the hosts/versions the engagement provisions. OUT of scope: attacking unrelated production hosts, or any host outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "API10",
        "name": "Unsafe Consumption of APIs",
        "summary": "The application consumes third-party/external APIs without sufficient validation of received data or the interaction's integrity — trusting external services, redirecting to weaker security, not sanitizing third-party responses.",
        "objective_template": (
            "Assess {target} for Unsafe Consumption of APIs (OWASP API10:2023). "
            "Identify where {target} integrates with third-party/external APIs "
            "(data enrich, payment, identity, SMS, maps, AI/LLM) and evaluate "
            "whether it validates the data received and protects the interaction: "
            "no blind trust of external responses, redirect/data-flow integrity, "
            "and no downgrading to weaker security to integrate. This is "
            "predominantly a white-box / design / third-party-contract concern; "
            "the black-box pass can only note integrations and externally "
            "observable data-flow weaknesses."
        ),
        "checklist": [
            "Identify third-party API integrations from client-served JS, network traffic, and documentation (payment, identity, SMS, maps, AI/LLM, data enrich).",
            "Assess whether external responses are validated/sanitized before use (reflected XSS / injection from third-party data) where observable.",
            "Check interaction integrity: does the integration redirect to or downgrade to a weaker-security endpoint?",
            "Evaluate blind-trust of the third party (does {target} act on external data without re-validation?).",
            "Flag the deep contract/dependency review (data-handling agreements, third-party trust model) as a white-box follow-up.",
        ],
        "tools": ["burpsuite", "curl", "nmap"],
        "scope_notes": "IN scope: observing and probing {target}'s own consumption of third-party APIs, with bounded non-destructive payloads. OUT of scope: attacking the third-party services themselves, exfiltrating data to external systems, or any action outside the authorized scope.",
        "assessable": "white-box-only",
    },
]


def catalog() -> Dict[str, Any]:
    """Return the catalog in the API response shape."""
    return {"categories": API_SECURITY_CATEGORIES}
