"""OWASP Top 10 (2021) catalog for the Coder56 pentest console.

Single source of truth for the "one run per OWASP Top 10 category" engagement
model surfaced in the standalone Coder56 console
(GET /api/coder56/owasp/catalog) and consumed by the engagement owasp-plan
drafting endpoint. Mirrors services/mitre_catalog.py.

Each category carries a templated objective (`objective_template`, `{target}` is
the authorized engagement scope), a WSTG-style `checklist` of concrete sub-tests,
recommended `tools`, `scope_notes` for the guardrail, and an `assessable` flag.

`assessable` honors the assessment caveat (CODER56_ASSESSMENT_OWASP_and_run-2203.md
A.4): A02 (Crypto), A06 (Components/SBOM), A08 (Integrity) and A09
(Logging/Monitoring) are white-box / config / SBOM concerns that a black-box
runner cannot meaningfully assess. They are still drafted (so coverage is
honest) but flagged `white-box-only` so the operator routes them to a
source/config review rather than silently producing empty runs.

Curated for an AUTHORIZED, isolated cyber-range lab. Representative commands and
tools are intentional — coder56 is a sanctioned red-team simulation subsystem.
"""
from __future__ import annotations

from typing import Any, Dict, List

# OWASP Top 10 (2021). Each entry:
#   {id, name, summary, objective_template, checklist, tools, scope_notes,
#    assessable}
# `assessable`: "black-box" (the runner can test it remotely) or
#               "white-box-only" (config/source/SBOM concern; draft for
#               coverage but route to a review module).
OWASP_CATEGORIES: List[Dict[str, Any]] = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "summary": "Restrictions on what authenticated users are allowed to do are not properly enforced — vertical/horizontal privilege escalation, IDOR, forced browsing past access checks.",
        "objective_template": (
            "Assess {target} for Broken Access Control (OWASP A01) flaws. Enumerate the "
            "application's objects, endpoints and roles, then test whether a user can act "
            "on resources or invoke functions outside their authorization: horizontal & "
            "vertical privilege escalation, insecure direct object references (IDOR), "
            "missing function-level access control, and forced browsing to protected "
            "URLs/APIs. Demonstrate impact with a proof-of-access to another tenant's or "
            "an admin's resource."
        ),
        "checklist": [
            "Map authenticated endpoints and object identifiers (account/order/file IDs, API resource paths).",
            "Horizontal escalation: with user A's session, manipulate IDs to access user B's resources (IDOR).",
            "Vertical escalation: attempt admin/privileged endpoints or parameters from a low-privilege session.",
            "Force-browse protected pages/APIs while unauthenticated or as a low-privilege user.",
            "Check metadata manipulation (user_id/role/is_admin in requests/cookies/JWT claims).",
            "Test the account you own vs. a second account in a different role (capture proof of cross-tenant access).",
        ],
        "tools": ["ffuf", "burpsuite", "autorize", "jwt_tool", "curl"],
        "scope_notes": "IN scope: testing access control ONLY against {target} using accounts/identifiers you own or that the engagement provisions. OUT of scope: accessing any other tenant's real data, brute-forcing credentials, or touching hosts outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "summary": "Sensitive data exposed or transmitted without strong cryptography — weak TLS, plaintext protocols, hardcoded/sensitive data at rest.",
        "objective_template": (
            "Assess {target} for Cryptographic Failures (OWASP A02). Review the transport "
            "and at-rest protection of sensitive data: TLS configuration and cipher "
            "strength, certificate validity, plaintext protocols carrying credentials, "
            "sensitive data in responses/caches, and weak/hardcoded secrets. Note that "
            "full at-rest / key-management review is a white-box concern; focus the "
            "black-box pass on observable transport and leakage."
        ),
        "checklist": [
            "Inspect TLS versions, cipher suites and certificate chain/validity for {target}.",
            "Detect plaintext protocols (HTTP/FTP/SMTP/Telnet) and credential-bearing forms over cleartext.",
            "Check for sensitive data (tokens, PII, secrets) returned in responses, URLs or client caches.",
            "Look for weak password hashing if hashes are reachable, or hardcoded secrets in client-served JS.",
            "Verify HSTS and secure-cookie flags on auth sessions.",
            "Flag the at-rest / key-management review as a white-box follow-up if not observable.",
        ],
        "tools": ["testssl.sh", "nmap --script ssl-*", "sslyze", "curl", "burpsuite"],
        "scope_notes": "IN scope: passive/active inspection of TLS and data exposure on {target}. OUT of scope: decrypting or exfiltrating real user data, attacking CAs/infrastructure outside scope, or destructive certificate-stress tests.",
        "assessable": "white-box-only",
    },
    {
        "id": "A03",
        "name": "Injection",
        "summary": "Untrusted data sent to an interpreter as part of a command or query — SQLi, NoSQLi, command, LDAP, XPath, SSTI, expression/language injection.",
        "objective_template": (
            "Assess {target} for Injection (OWASP A03). Identify every input that flows "
            "into an interpreter (query, command, template, expression, header) and test "
            "for SQL/NoSQL/LDAP/XPath injection, OS command injection, SSTI, and "
            "expression-language injection, including error-, boolean-, union-, time- and "
            "out-of-band variants. Demonstrate impact with a bounded, non-destructive proof."
        ),
        "checklist": [
            "Enumerate input vectors: parameters, headers, cookies, JSON/body fields, path segments.",
            "SQLi: error-based, boolean, UNION, and time/blind probes against data-driven parameters.",
            "NoSQLi: operator injection ({ '$gt': '' }) and JS-injection on document stores.",
            "OS command injection: meta-characters (; | ` $()) in inputs that reach a shell.",
            "SSTI: template syntax probes ({{7*7}}, ${7*7}, <%= 7*7 %>) against reflected/template fields.",
            "Confirm with a benign, observable payload (e.g. a computed value or a sleep) — no destructive impact.",
        ],
        "tools": ["sqlmap", "ffuf", "burpsuite", "commix", "curl"],
        "scope_notes": "IN scope: injection testing ONLY against {target} with bounded, non-destructive payloads. OUT of scope: data exfiltration to external systems, destructive queries/commands, DoS, or touching hosts outside scope.",
        "assessable": "black-box",
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "summary": "Missing or ineffective control design (not implementation bugs) — business-logic flaws, abuse cases, lack of rate limiting / threat modeling.",
        "objective_template": (
            "Assess {target} for Insecure Design (OWASP A04). Probe the application's "
            "business logic and control design for abuse: workflow bypasses, race "
            "conditions on state-changing actions, missing rate limits / anti-automation "
            "on sensitive functions, and trust-boundary assumptions. Focus on whether the "
            "design itself permits abuse, not on implementation bugs."
        ),
        "checklist": [
            "Identify multi-step business workflows (checkout, transfer, password reset, voucher redemption).",
            "Test skipping/reordering steps, replaying state-changing requests, and parameter tampering in workflows.",
            "Check for missing rate limits / anti-automation on login, reset, OTP, and cost-incurring endpoints.",
            "Probe race conditions on balances, quotas, coupons, or one-time actions (send in parallel).",
            "Examine trust boundaries: does the client enforce a limit the server does not re-validate?",
            "Document design-level abuse cases with a minimal, reversible proof.",
        ],
        "tools": ["burpsuite", "turbo-intruder", "ffuf", "curl"],
        "scope_notes": "IN scope: logic/abuse testing ONLY against {target}, with reversible, non-destructive actions. OUT of scope: fraudulent value transfer to real accounts, DoS via flooding, or actions outside the authorized scope.",
        "assessable": "black-box",
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "summary": "Missing hardening, default accounts, verbose errors, unpatched flaws, enabled unnecessary features, unprotected files/dirs.",
        "objective_template": (
            "Assess {target} for Security Misconfiguration (OWASP A05). Look for missing "
            "hardening and unnecessary attack surface: default/factory credentials and "
            "admin panels, verbose error stacks and debug flags, exposed config/backup/"
            "metadata files, stale default content, and unnecessary enabled features "
            "(HTTP methods, directory listing, auto-indexing, management interfaces)."
        ),
        "checklist": [
            "Probe for default admin consoles / management interfaces (/, /admin, /manager, /console, /actuator).",
            "Try default/factory credentials on discovered login surfaces.",
            "Hunt for exposed config/backup/git/.env/.well-known files and directory listings.",
            "Trigger verbose error pages / stack traces to fingerprint frameworks and versions.",
            "Check unnecessary HTTP methods (PUT/DELETE/TRACE), CORS reflection, and missing security headers.",
            "Inventory the exposed software/versions for the A06 components pass.",
        ],
        "tools": ["nuclei", "ffuf", "nmap", "curl", "nikto"],
        "scope_notes": "IN scope: misconfiguration discovery ONLY on {target}. OUT of scope: exploiting to pivot/destroy, brute-forcing credentials at scale, or touching hosts outside scope.",
        "assessable": "black-box",
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "summary": "Using libraries/frameworks/components with known vulnerabilities or out-of-date versions.",
        "objective_template": (
            "Assess {target} for Vulnerable & Outdated Components (OWASP A06). Inventory "
            "the software stack exposed by the application (frameworks, libraries, "
            "servers, CMS/plugins, JS dependencies), fingerprint versions, and match them "
            "against known CVEs. Note that SBOM/library dependency review is a white-box "
            "concern; the black-box pass fingerprints observable versions and flags known "
            "exploitable ones."
        ),
        "checklist": [
            "Fingerprint frameworks, servers and CMS/plugin versions from headers, footers, JS bundles and manifests.",
            "Enumerate client-side JS libraries/versions and known-stale fingerprints.",
            "Match discovered versions against known CVEs (local exploit-db / advisory mirror).",
            "Confirm reachability of any vulnerable component on {target} (do not mass-exploit).",
            "Flag the deep dependency/SBOM review as a white-box follow-up.",
        ],
        "tools": ["retire.js", "nuclei", "wpscan", "nmap -sV", "searchsploit"],
        "scope_notes": "IN scope: version fingerprinting and CVE matching ONLY on {target}. OUT of scope: deploying destructive public exploits against scoped services, or scanning hosts outside scope.",
        "assessable": "white-box-only",
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "summary": "Weak credential handling, missing MFA, session/token flaws, credential stuffing exposure, predictable auth state.",
        "objective_template": (
            "Assess {target} for Identification & Authentication Failures (OWASP A07). "
            "Evaluate the authentication and session lifecycle: credential policy and "
            "stuffing exposure, MFA presence and bypass, session/token generation and "
            "invalidation, and auth-state predictability. Use ONLY accounts you own; do "
            "not perform mass online password attacks."
        ),
        "checklist": [
            "Check password/credential policy strength and whether breached-credential protection exists.",
            "Assess MFA presence and test for MFA bypass / brute-force on OTP/reset codes (bounded).",
            "Inspect session token entropy, predictability, and rotation on login/logout/privilege change.",
            "Test session invalidation: does logout / timeout actually kill the session server-side?",
            "Check for credential stuffing exposure (no rate limit, no lockout) — report, do not mass-test.",
            "Verify 'remember-me', password reset, and account-recovery flows for token reuse/predictability.",
        ],
        "tools": ["burpsuite", "jwt_tool", "ffuf", "curl"],
        "scope_notes": "IN scope: auth/session testing ONLY against {target} with accounts you own and bounded attempts. OUT of scope: online password brute-force / credential stuffing at scale, account lockout DoS, or attacking other users' accounts.",
        "assessable": "black-box",
    },
    {
        "id": "A08",
        "name": "Software and Data Integrity Failures",
        "summary": "Code/config/data whose integrity is not verified — unsigned updates, CI/CD pipeline trust, insecure deserialization of untrusted data.",
        "objective_template": (
            "Assess {target} for Software & Data Integrity Failures (OWASP A08). Look for "
            "deserialization of untrusted data and integrity-related trust assumptions: "
            "insecure deserialization gadgets, unsigned/auto-trusted updates or plugins, "
            "and tamperable signed/serialized tokens. Pipeline/CI trust review is a "
            "white-box concern; the black-box pass probes deserialization and token "
            "integrity where observable."
        ),
        "checklist": [
            "Identify serialized/encoded data flows (Java/PHP/.NET/Python pickle, signed cookies, JWTs).",
            "Probe deserialization inputs for type/manipulation issues (avoid destructive gadgets).",
            "Check JWT/signed-token integrity: 'alg': none, key confusion, weak HMAC secrets, missing signature checks.",
            "Inspect update/plugin fetch paths for unsigned/auto-trusted sources where observable.",
            "Flag CI/CD and software-supply-chain trust as a white-box follow-up.",
        ],
        "tools": ["jwt_tool", "ysoserial", "burpsuite", "curl"],
        "scope_notes": "IN scope: integrity/deserialization probing ONLY against {target} with non-destructive payloads. OUT of scope: remote code execution that damages scoped services, or attacking the build/release infrastructure.",
        "assessable": "white-box-only",
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "summary": "Insufficient logging, alerting and monitoring of security-relevant events — only assessable with logs/telemetry access.",
        "objective_template": (
            "Assess {target} for Security Logging & Monitoring Failures (OWASP A09). "
            "Determine whether security-relevant events (auth, access-control denials, "
            "input-validation failures, admin actions) are logged, retained and "
            "monitorable. This is predominantly a white-box / operational concern "
            "requiring log access; the black-box pass can only note observability gaps."
        ),
        "checklist": [
            "Perform security-relevant actions (failed logins, IDOR attempts, blocked requests) and assess whether they are logged (requires log/telemetry access).",
            "Check for audit trails on authentication, access-control, and privileged actions.",
            "Assess log retention, centralization, and alerting coverage (operational review).",
            "Verify sensitive data is not itself written into logs.",
            "Flag this as a white-box/operational follow-up if logs are not accessible.",
        ],
        "tools": ["burpsuite", "curl"],
        "scope_notes": "IN scope: generating test events on {target} to assess logging. OUT of scope: tampering with or deleting logs, or attacking the SIEM/monitoring infrastructure.",
        "assessable": "white-box-only",
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "summary": "The server fetches a remote resource without validating the user-supplied URL — internal port/scan, cloud-metadata, or protocol access.",
        "objective_template": (
            "Assess {target} for Server-Side Request Forgery (OWASP A10). Locate inputs "
            "where the server fetches a URL you control (webhooks, importers, image/link "
            "fetchers, PDF/render endpoints) and test for SSRF: reaching internal "
            "services/ports, cloud metadata endpoints, and protocol/gopher smuggling. "
            "Demonstrate with a benign callback or a metadata read — no destructive "
            "internal actions."
        ),
        "checklist": [
            "Enumerate URL-fetch inputs (webhooks, avatars, import, link/image/PDF preview, SSO callbacks).",
            "Point them at an out-of-band listener you own to confirm server-side fetch.",
            "Test reaching internal IPs/ports and loopback from the server's vantage point.",
            "Attempt cloud metadata endpoints (169.254.169.254) where the platform applies.",
            "Try URL-parser bypasses (@, #[], DNS rebinding, alternate schemes) — bounded.",
            "Demonstrate impact with a benign fetch/metadata read; do not pivot destructively.",
        ],
        "tools": ["burpsuite", "ffuf", "gopherus", "curl"],
        "scope_notes": "IN scope: SSRF testing ONLY against {target}, via callbacks to hosts you own and reads of non-sensitive metadata. OUT of scope: exfiltrating credentials to external systems, destructive internal actions, or pivoting beyond the authorized scope.",
        "assessable": "black-box",
    },
]


def catalog() -> Dict[str, Any]:
    """Return the catalog in the API response shape."""
    return {"categories": OWASP_CATEGORIES}
