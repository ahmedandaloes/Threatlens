"""Built-in, rule-based STRIDE knowledge base.

This is what makes ThreatLens work fully offline. Each rule is a small,
reviewable predicate written the way an application-security consultant
would reason during a threat-modeling workshop: "this kind of component,
holding this kind of data, missing this control => this threat".

Mappings:
* CWE ids are per rule.
* OWASP Top 10 2021 categories are derived from CWE (CWE_TO_TOP10).
* OWASP ASVS 4.0.3 references are given at section level (e.g. V4.2).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import Architecture, Component, Endpoint, Flow

# --------------------------------------------------------------------------
# OWASP mappings
# --------------------------------------------------------------------------
TOP10 = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

CWE_TO_TOP10 = {
    "CWE-200": "A01", "CWE-284": "A01", "CWE-285": "A01", "CWE-352": "A01",
    "CWE-639": "A01", "CWE-862": "A01", "CWE-863": "A01", "CWE-668": "A01",
    "CWE-732": "A01", "CWE-250": "A01", "CWE-359": "A01",
    "CWE-311": "A02", "CWE-312": "A02", "CWE-319": "A02", "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-79": "A03", "CWE-89": "A03", "CWE-94": "A03", "CWE-915": "A08",
    "CWE-209": "A04", "CWE-434": "A04", "CWE-522": "A04", "CWE-602": "A04",
    "CWE-657": "A04", "CWE-770": "A04", "CWE-799": "A04", "CWE-840": "A04",
    "CWE-400": "A05", "CWE-16": "A05", "CWE-524": "A05",
    "CWE-1104": "A06",
    "CWE-287": "A07", "CWE-306": "A07", "CWE-307": "A07", "CWE-308": "A07",
    "CWE-798": "A07", "CWE-613": "A07",
    "CWE-345": "A08", "CWE-494": "A08", "CWE-502": "A08",
    "CWE-532": "A09", "CWE-778": "A09",
    "CWE-918": "A10",
}

# --------------------------------------------------------------------------
# Mitigation catalogue (effort in person-days for a small SME dev team)
# --------------------------------------------------------------------------
MITIGATIONS: dict[str, dict] = {
    "mfa": dict(title="Enforce MFA for privileged and staff accounts",
                detail="TOTP / passkeys for admin, doctor, finance and HR roles; SMS OTP only as fallback.",
                effort=2, owner="Backend"),
    "rate_limiting": dict(title="Rate limiting & anti-automation on auth/OTP/sensitive endpoints",
                          detail="Per-IP and per-account limits at the gateway (e.g. Nginx/Cloudflare) plus progressive delays and CAPTCHA after failures.",
                          effort=1, owner="DevOps"),
    "account_lockout": dict(title="Account lockout & credential-stuffing detection",
                            detail="Temporary lockout, breached-password check (HIBP k-anonymity), alert on spikes of failed logins.",
                            effort=1, owner="Backend"),
    "admin_network": dict(title="Restrict admin panel to VPN / IP allow-list",
                          detail="Serve the back office on a separate host, behind VPN or Cloudflare Access / Zero-Trust.",
                          effort=1, owner="DevOps"),
    "no_client_secrets": dict(title="Remove secrets from mobile/web clients",
                              detail="Move third-party keys server-side, use short-lived tokens, enable Play Integrity / App Attest.",
                              effort=2, owner="Mobile"),
    "webhook_signature": dict(title="Verify payment & partner webhook signatures",
                              detail="Validate HMAC (e.g. Paymob HMAC, Fawry signature) and re-query transaction status server-to-server before fulfilling.",
                              effort=1, owner="Backend"),
    "service_auth": dict(title="Authenticate service-to-service traffic",
                         detail="mTLS or signed service tokens between internal services; network policies.",
                         effort=3, owner="DevOps"),
    "parameterized_queries": dict(title="Parameterized queries / ORM-only data access",
                                  detail="Ban string-built SQL, add SAST rule (Semgrep) in CI.",
                                  effort=2, owner="Backend"),
    "input_validation": dict(title="Schema-based input validation & allow-listed fields",
                             detail="Validate every request body against a schema (pydantic/Joi/FormRequest); block mass assignment with explicit DTOs.",
                             effort=3, owner="Backend"),
    "server_side_pricing": dict(title="Recompute amounts and prices server-side",
                                detail="Never trust totals, discounts or amounts from the client; sign the order before redirecting to the gateway.",
                                effort=2, owner="Backend"),
    "secure_upload": dict(title="Harden file uploads",
                          detail="Type/size allow-list, re-encode images, malware scan, store outside web root with random names, serve via signed URLs.",
                          effort=2, owner="Backend"),
    "output_encoding": dict(title="Output encoding + Content-Security-Policy",
                            detail="Framework auto-escaping, strict CSP, sanitize rich text (DOMPurify).",
                            effort=2, owner="Frontend"),
    "csrf": dict(title="CSRF protection for cookie sessions",
                 detail="SameSite=Lax/Strict cookies and anti-CSRF tokens on state-changing requests.",
                 effort=1, owner="Backend"),
    "audit_logging": dict(title="Tamper-evident audit log for sensitive actions",
                          detail="Log who/what/when for access to patient/employee/payment records and admin changes; ship to append-only storage.",
                          effort=3, owner="Backend"),
    "encryption_at_rest": dict(title="Encrypt sensitive data at rest",
                               detail="Managed disk/DB encryption plus field-level encryption for national IDs, IBANs, medical notes.",
                               effort=3, owner="Backend"),
    "private_storage": dict(title="Private buckets + short-lived signed URLs",
                            detail="Block public access, per-object authorization, URL expiry <= 15 min.",
                            effort=1, owner="DevOps"),
    "object_level_authz": dict(title="Object-level authorization on every record access (anti-IDOR/BOLA)",
                               detail="Central policy check that the caller owns / may access the record; use non-guessable IDs; add automated authz tests.",
                               effort=4, owner="Backend"),
    "error_handling": dict(title="Generic error responses, no stack traces in production",
                           detail="Global exception handler, debug mode off, correlation IDs instead of details.",
                           effort=0.5, owner="Backend"),
    "log_redaction": dict(title="Redact sensitive fields from logs",
                          detail="Mask national IDs, card data, tokens and medical details in application and gateway logs.",
                          effort=1, owner="Backend"),
    "secure_storage": dict(title="Use Keystore/Keychain for on-device sensitive data",
                           detail="No tokens or PHI in SharedPreferences/AsyncStorage; encrypted storage, wipe on logout.",
                           effort=2, owner="Mobile"),
    "data_minimization": dict(title="Data minimization & DPA with third parties",
                              detail="Send only the fields the provider needs; sign a data-processing agreement (Egypt PDPL 151/2020, KSA PDPL).",
                              effort=2, owner="Product/Legal"),
    "cache_auth": dict(title="Lock down the cache",
                       detail="Require AUTH/ACLs, private network only, TTLs for sensitive keys.",
                       effort=0.5, owner="DevOps"),
    "waf_cdn": dict(title="WAF / CDN with DDoS protection in front of public endpoints",
                    detail="Cloudflare / AWS WAF managed rules, bot protection, origin locked to CDN.",
                    effort=1, owner="DevOps"),
    "backups": dict(title="Encrypted, tested, off-site backups (ransomware-resilient)",
                    detail="Daily encrypted backups, immutable copy, quarterly restore test, documented RPO/RTO.",
                    effort=2, owner="DevOps"),
    "otp_abuse": dict(title="OTP/SMS pumping controls",
                      detail="Per-number and per-country limits, CAPTCHA before sending, alert on SMS spend anomalies.",
                      effort=1, owner="Backend"),
    "rbac": dict(title="Role-based access control on every privileged function",
                 detail="Deny-by-default middleware, role checks on server for admin APIs, tests per role.",
                 effort=3, owner="Backend"),
    "ssrf_protection": dict(title="SSRF protection for outbound requests",
                            detail="Allow-list destinations, block internal IP ranges/metadata endpoints, use egress proxy.",
                            effort=2, owner="Backend"),
    "secrets_manager": dict(title="Move secrets to a secrets manager & rotate",
                            detail="Vault / AWS Secrets Manager / Doppler, no keys in git or .env on servers, secret scanning in CI.",
                            effort=2, owner="DevOps"),
    "monitoring": dict(title="Centralized security monitoring & alerting",
                       detail="Ship auth, admin and payment events to a SIEM/log platform; alert on anomalies; on-call runbook.",
                       effort=3, owner="DevOps"),
    "sca": dict(title="Dependency scanning & patching cadence (SCA)",
                detail="Dependabot/Renovate + OSV/Trivy in CI, monthly patch window.",
                effort=1, owner="DevOps"),
    "tls": dict(title="Encrypt all data in transit (TLS 1.2+)",
                detail="HTTPS/SFTP/TLS everywhere incl. internal hops carrying sensitive data; HSTS on public sites.",
                effort=1, owner="DevOps"),
    "least_privilege_db": dict(title="Least-privilege database accounts",
                               detail="Separate read/write accounts per service, no app access with DBA rights, no direct internet exposure.",
                               effort=1, owner="DevOps"),
    "network_segmentation": dict(title="Remove direct internet exposure of data stores",
                                 detail="Place databases in private subnets, access only from app tier / bastion.",
                                 effort=1, owner="DevOps"),
    "file_integrity": dict(title="Sign / checksum payroll and payment batch files at source",
                           detail="Generate the WPS/bank file in one service, sign it (or HMAC + maker-checker approval), verify before upload, alert on IBAN changes.",
                           effort=2, owner="Backend"),
    "session_mgmt": dict(title="Harden session & token lifecycle",
                         detail="Short-lived access tokens, refresh token rotation, server-side revocation on logout / password change.",
                         effort=2, owner="Backend"),
}

# --------------------------------------------------------------------------
# Rule definitions
# --------------------------------------------------------------------------
PUBLIC_ENTRY = {"web_frontend", "api", "mobile_app", "admin_panel"}
CUSTOM_CODE = {"web_frontend", "api", "service", "admin_panel", "mobile_app"}
STORES = {"database", "object_storage", "cache", "queue"}


@dataclass
class Rule:
    id: str
    stride: str
    title: str
    description: str
    cwe: list[str]
    asvs: list[str]
    likelihood: int
    mitigations: list[str]
    applies: Callable[..., bool]
    scope: str = "component"          # component | flow | system | endpoint
    impact: int | None = None         # fixed impact; None => derived from data sensitivity
    internet_bonus: bool = True       # +1 likelihood when internet facing
    impact_delta: int = 0             # -1 when blast radius is a single user/session
    tags: list[str] = field(default_factory=list)


def _weak_auth(c: Component) -> bool:
    return c.auth in ("none", "password", "session", "jwt", "api_key") and not c.has("mfa")


COMPONENT_RULES: list[Rule] = [
    # ---------------- Spoofing ----------------
    Rule("S-01", "S", "Account takeover via single-factor authentication",
         "{name} authenticates users with {auth} only. Phished, reused or leaked passwords give an attacker full access to {data}.",
         ["CWE-308", "CWE-287"], ["V2.1 Password Security", "V2.8 One Time Verifier"], 3, ["mfa"],
         lambda c, a: c.type in ("web_frontend", "mobile_app", "api") and c.internet_facing and c.is_sensitive
         and c.auth in ("password", "session", "jwt") and not c.has("mfa"), impact_delta=-1),
    Rule("S-02", "S", "Credential stuffing / brute force on login and OTP",
         "No rate limiting is documented for {name}. Automated credential-stuffing or OTP guessing can take over accounts.",
         ["CWE-307"], ["V2.2 General Authenticator Security"], 3, ["rate_limiting", "account_lockout"],
         lambda c, a: c.type in ("api", "web_frontend", "admin_panel") and c.internet_facing
         and c.auth not in ("none", "sso", "oauth") and not c.has("rate_limiting") and not a.has_global("rate_limiting"), impact_delta=-1),
    Rule("S-03", "S", "Internet-exposed admin panel without MFA",
         "{name} is reachable from the internet and protected only by {auth}. Staff accounts are the highest-value phishing target.",
         ["CWE-308", "CWE-306"], ["V4.3 Other Access Control Considerations", "V2.8 One Time Verifier"], 4,
         ["mfa", "admin_network"],
         lambda c, a: c.type == "admin_panel" and c.internet_facing and not c.has("mfa", "vpn", "ip_allowlist")),
    Rule("S-04", "S", "Secrets extractable from the client app",
         "{name} ships to user devices. API keys or partner credentials embedded in the bundle can be extracted and abused to impersonate the app.",
         ["CWE-798"], ["V14.3 Unintended Security Disclosure", "V6.4 Secret Management"], 3, ["no_client_secrets"],
         lambda c, a: c.type in ("mobile_app",) and not c.has("app_attestation"), internet_bonus=False, impact=4),
    Rule("S-05", "S", "Unauthenticated access to internal service",
         "{name} accepts connections without authentication. Any foothold in the network can call it directly.",
         ["CWE-306"], ["V1.4 Access Control Architecture", "V9.2 Server Communication Security"], 3, ["service_auth"],
         lambda c, a: c.type in ("service", "queue") and c.auth == "none"),
    # ---------------- Tampering ----------------
    Rule("T-01", "T", "SQL / NoSQL injection into backend data store",
         "{name} builds queries against a data store and no input-validation / parameterization control is documented.",
         ["CWE-89"], ["V5.3 Output Encoding and Injection Prevention"], 2,
         ["parameterized_queries", "input_validation"],
         lambda c, a: c.type in ("api", "service", "admin_panel") and _writes_to_store(c, a)
         and not c.has("input_validation", "parameterized_queries", "orm")),
    Rule("T-02", "T", "Payment amount / order tampering",
         "{name} handles payments. If totals, discounts or amounts are accepted from the client, attackers can pay less than the real price.",
         ["CWE-602", "CWE-840"], ["V11.1 Business Logic Security"], 3, ["server_side_pricing"],
         lambda c, a: c.type == "api" and "payment" in c.data and not c.has("server_side_pricing"), impact=5),
    Rule("T-03", "T", "Malicious file upload",
         "{name} accepts file uploads (e.g. documents, images, lab results). Unrestricted uploads enable web shells, malware hosting and stored XSS.",
         ["CWE-434"], ["V12.1 File Upload", "V12.2 File Integrity"], 2, ["secure_upload"],
         lambda c, a: c.feature("file_upload") and not c.has("upload_scanning")),
    Rule("T-04", "T", "Stored / reflected XSS in browser UI",
         "{name} renders user-supplied content. Without output encoding and CSP, script injection can steal sessions of staff or customers.",
         ["CWE-79"], ["V5.3 Output Encoding and Injection Prevention", "V14.4 HTTP Security Headers"], 3,
         ["output_encoding"],
         lambda c, a: c.type in ("web_frontend", "admin_panel") and not c.has("csp", "output_encoding"), impact_delta=-1),
    Rule("T-05", "T", "Cross-site request forgery on cookie-based session",
         "{name} uses cookie sessions; state-changing requests could be forged from another site.",
         ["CWE-352"], ["V4.2 Operation Level Access Control", "V3.4 Cookie-based Session Management"], 3, ["csrf"],
         lambda c, a: c.type in ("web_frontend", "admin_panel") and c.auth == "session" and not c.has("csrf"), impact_delta=-1),
    Rule("T-06", "E", "Mass assignment of privileged fields",
         "{name} binds request bodies to models. Without explicit DTOs a user can set fields such as role, is_admin, salary or price.",
         ["CWE-915"], ["V5.1 Input Validation"], 2, ["input_validation"],
         lambda c, a: c.type == "api" and not c.has("input_validation")),
    # ---------------- Repudiation ----------------
    Rule("R-01", "R", "No audit trail for access to sensitive records",
         "{name} processes {data} but no audit logging is documented. Insider misuse or a breach cannot be investigated or proven.",
         ["CWE-778"], ["V7.1 Log Content", "V7.2 Log Processing"], 3, ["audit_logging"],
         lambda c, a: c.type in ("api", "admin_panel") and c.is_sensitive and not c.has("audit_logging"),
         internet_bonus=False, impact=3),
    Rule("R-02", "R", "Sensitive logs leak data",
         "{name} logs requests, but log redaction is not documented. Logs become a second, poorly-protected copy of {data}.",
         ["CWE-532"], ["V7.1 Log Content"], 2, ["log_redaction"],
         lambda c, a: c.type in ("api", "service") and c.is_sensitive and c.has("logging", "audit_logging")
         and not c.has("log_redaction"), internet_bonus=False),
    # ---------------- Information disclosure ----------------
    Rule("I-01", "I", "Sensitive data stored unencrypted at rest",
         "{name} stores {data} without documented encryption at rest. A stolen backup, snapshot or disk exposes everything.",
         ["CWE-311", "CWE-312"], ["V6.1 Data Classification", "V8.3 Sensitive Private Data"], 2,
         ["encryption_at_rest"],
         lambda c, a: c.type in ("database", "object_storage") and c.is_sensitive and not c.has("encryption_at_rest"),
         internet_bonus=False),
    Rule("I-02", "I", "Publicly readable storage bucket / predictable file URLs",
         "{name} holds files ({data}). Misconfigured public access or guessable URLs are a top cause of SME data leaks.",
         ["CWE-732", "CWE-200"], ["V12.4 File Storage", "V4.1 General Access Control Design"], 3, ["private_storage"],
         lambda c, a: c.type == "object_storage" and not c.has("private_bucket", "signed_urls"), internet_bonus=False),
    Rule("I-03", "I", "IDOR / Broken object-level authorization",
         "{name} exposes records by ID ({data}). If ownership is not checked server-side, changing an ID returns another customer's data.",
         ["CWE-639", "CWE-862"], ["V4.2 Operation Level Access Control"], 4, ["object_level_authz"],
         lambda c, a: c.type == "api" and c.is_sensitive and not c.has("object_level_authz")),
    Rule("I-04", "I", "Verbose errors / debug mode in production",
         "{name}: stack traces and framework debug pages disclose internals and sometimes secrets.",
         ["CWE-209"], ["V7.4 Error Handling"], 3, ["error_handling"],
         lambda c, a: c.type in ("api", "web_frontend", "admin_panel") and c.internet_facing and not c.has("error_handling"), impact=2),
    Rule("I-05", "I", "Sensitive data stored insecurely on device",
         "{name} may cache tokens or {data} on the device in plain storage, exposed on lost/rooted phones.",
         ["CWE-312"], ["V8.2 Client-side Data Protection"], 2, ["secure_storage"],
         lambda c, a: c.type == "mobile_app" and c.is_sensitive and not c.has("secure_storage"), internet_bonus=False, impact_delta=-1),
    Rule("I-06", "I", "Personal data shared with third party beyond need",
         "{name} receives {data}. Over-sharing with processors without a DPA creates privacy and regulatory exposure (Egypt PDPL / KSA PDPL).",
         ["CWE-359"], ["V8.3 Sensitive Private Data"], 3, ["data_minimization"],
         lambda c, a: c.type == "third_party" and any(d in c.data for d in ("pii", "phi", "national_id", "financial"))
         and not c.has("dpa"), internet_bonus=False, impact=3),
    Rule("I-07", "I", "Unauthenticated cache exposes session / personal data",
         "{name} caches {data} with auth '{auth}'. Unauthenticated Redis/Memcached is routinely found and dumped.",
         ["CWE-524", "CWE-306"], ["V8.1 General Data Protection"], 3, ["cache_auth"],
         lambda c, a: c.type == "cache" and c.auth == "none", internet_bonus=False),
    # ---------------- DoS ----------------
    Rule("D-01", "D", "Resource exhaustion on public API",
         "{name} is internet-facing without documented rate limits; scraping or floods can take the service down or inflate cloud bills.",
         ["CWE-770"], ["V11.1 Business Logic Security", "V13.1 Generic Web Service Security"], 3, ["rate_limiting"],
         lambda c, a: c.type == "api" and c.internet_facing and not c.has("rate_limiting") and not a.has_global("rate_limiting"),
         impact=3),
    Rule("D-02", "D", "No WAF / DDoS protection at the edge",
         "{name} is exposed directly. Volumetric and application-layer DDoS (common around Ramadan / White Friday sales) has no absorption layer.",
         ["CWE-400"], ["V13.1 Generic Web Service Security"], 2, ["waf_cdn"],
         lambda c, a: c.type in ("web_frontend", "api") and c.internet_facing and not c.has("waf", "cdn") and not a.has_global("waf", "cdn"),
         impact=3),
    Rule("D-03", "D", "No tested backups for crown-jewel data (ransomware)",
         "{name} holds {data} with no documented backup/restore. Ransomware or an accidental delete is a business-ending event.",
         ["CWE-657"], ["V8.1 General Data Protection"], 3, ["backups"],
         lambda c, a: c.type == "database" and not c.has("backups") and not a.has_global("backups"),
         internet_bonus=False, impact=5),
    Rule("D-04", "D", "SMS/WhatsApp OTP pumping & messaging abuse",
         "{name} sends OTP / notifications. Bots can trigger thousands of messages (toll fraud) or spam patients/customers.",
         ["CWE-799"], ["V2.2 General Authenticator Security"], 4, ["otp_abuse"],
         lambda c, a: c.type == "third_party" and c.category == "messaging" and not c.has("otp_limits"),
         internet_bonus=False, impact=3),
    # ---------------- Elevation of privilege ----------------
    Rule("E-01", "E", "Broken function-level authorization (user reaches admin functions)",
         "{name} serves both end users and staff/admin functions. Missing server-side role checks let normal users call privileged endpoints.",
         ["CWE-285", "CWE-863"], ["V4.1 General Access Control Design", "V4.2 Operation Level Access Control"], 3, ["rbac"],
         lambda c, a: c.type == "api" and _has_admin(a) and not c.has("rbac"), internet_bonus=False),
    Rule("E-02", "E", "Server-side request forgery via outbound integrations",
         "{name} fetches URLs or calls user/partner-configurable endpoints. SSRF can reach cloud metadata and internal services.",
         ["CWE-918"], ["V12.6 SSRF Protection"], 3, ["ssrf_protection"],
         lambda c, a: c.feature("url_fetch", "webhooks_out") and not c.has("ssrf_protection")),
    Rule("E-03", "E", "Over-privileged database account",
         "{name}: applications typically connect with owner/DBA rights; any injection becomes full database compromise.",
         ["CWE-250"], ["V1.4 Access Control Architecture"], 2, ["least_privilege_db"],
         lambda c, a: c.type == "database" and c.is_sensitive and not c.has("least_privilege"), internet_bonus=False),
    Rule("E-04", "S", "Weak session / token lifecycle",
         "{name} uses {auth} tokens; without expiry, rotation and server-side revocation a stolen token stays valid indefinitely.",
         ["CWE-613"], ["V3.3 Session Termination", "V3.5 Token-based Session Management"], 3, ["session_mgmt"],
         lambda c, a: c.type == "api" and c.auth in ("jwt", "session") and not c.has("token_rotation"), impact_delta=-1),
]

SYSTEM_RULES: list[Rule] = [
    Rule("SYS-01", "I", "Secrets in source code / server env files",
         "No secrets manager is documented. Payment-gateway keys, DB passwords and JWT signing keys tend to live in git or .env files.",
         ["CWE-798"], ["V6.4 Secret Management", "V14.1 Build and Deploy"], 3, ["secrets_manager"],
         lambda a: not a.has_global("secrets_manager"), scope="system", impact=5, internet_bonus=False),
    Rule("SYS-02", "R", "No centralized security monitoring / alerting",
         "There is no documented security monitoring. Breaches at SMEs are typically discovered months later, by customers or regulators.",
         ["CWE-778"], ["V7.2 Log Processing", "V7.3 Log Protection"], 3, ["monitoring"],
         lambda a: not a.has_global("monitoring", "siem"), scope="system", impact=4, internet_bonus=False),
    Rule("SYS-03", "T", "Vulnerable third-party libraries (no SCA)",
         "No dependency scanning is documented for the custom code (npm/composer/pip/pub). Known-vulnerable packages are a common entry point.",
         ["CWE-1104"], ["V14.2 Dependency"], 3, ["sca"],
         lambda a: not a.has_global("sca"), scope="system", impact=4, internet_bonus=False),
]

FLOW_RULES: list[Rule] = [
    Rule("F-01", "I", "Sensitive data sent in cleartext",
         "Flow {src} -> {dst} uses {protocol} and carries {data}. Anyone on the path (Wi-Fi, ISP, internal network) can read or modify it.",
         ["CWE-319"], ["V9.1 Client Communication Security", "V9.2 Server Communication Security"], 3, ["tls"],
         lambda f, s, t, a: f.protocol.lower() in ("http", "ftp", "tcp", "smtp", "telnet", "ws", "mqtt", "ldap")
         and f.sensitivity >= 4 and "tls" not in f.controls, scope="flow"),
    Rule("F-02", "S", "Unauthenticated call across a trust boundary",
         "Flow {src} -> {dst} crosses from '{szone}' to '{tzone}' without authentication.",
         ["CWE-306"], ["V1.4 Access Control Architecture", "V13.1 Generic Web Service Security"], 3, ["service_auth"],
         lambda f, s, t, a: s.zone != t.zone and f.auth == "none"
         and t.type in ("service", "database", "queue", "cache", "admin_panel") and s.type != "user", scope="flow"),
    Rule("F-03", "S", "Forged webhook / callback from third party",
         "{dst} accepts callbacks from {src} ({data}). Without signature verification an attacker can forge 'payment successful' or status events.",
         ["CWE-345"], ["V10.3 Application Integrity", "V13.1 Generic Web Service Security"], 4, ["webhook_signature"],
         lambda f, s, t, a: s.type == "third_party" and t.type in ("api", "service")
         and f.auth not in ("hmac", "signature", "mtls") and "signature" not in f.controls, scope="flow", impact=5),
    Rule("F-04", "E", "Data store directly reachable from untrusted zone",
         "{dst} receives traffic directly from {src} in zone '{szone}'. Data stores should only be reachable from the application tier.",
         ["CWE-668"], ["V1.4 Access Control Architecture"], 4, ["network_segmentation", "least_privilege_db"],
         lambda f, s, t, a: t.type in ("database", "cache", "object_storage") and (s.zone in ("internet", "third_party")
         or s.type in ("user", "web_frontend", "mobile_app")), scope="flow"),
]

FLOW_RULES.append(Rule(
    "F-05", "T", "Batch payment / payroll file tampering before upload",
    "Flow {src} -> {dst} transfers a {protocol} file with {data}. Without a signature or checksum generated at source, "
    "an insider or compromised host can change IBANs or amounts before the bank / government platform processes it.",
    ["CWE-345", "CWE-494"], ["V10.3 Application Integrity", "V11.1 Business Logic Security"], 3, ["file_integrity"],
    lambda f, s, t, a: t.type == "third_party" and t.category in ("banking", "government", "payment")
    and "financial" in f.data and f.protocol.lower() in ("sftp", "ftp", "ftps", "smb", "email")
    and "signature" not in f.controls, scope="flow", impact=5))

ENDPOINT_RULES: list[Rule] = [
    Rule("API-01", "S", "API operations without any security requirement",
         "The OpenAPI spec declares no authentication on: {endpoints}.",
         ["CWE-306"], ["V13.1 Generic Web Service Security", "V4.1 General Access Control Design"], 4, ["rbac"],
         lambda e: not e.secured and not _public_path(e.path), scope="endpoint"),
    Rule("API-02", "I", "Endpoints addressing objects by ID (BOLA candidates)",
         "These operations take an object identifier and must enforce ownership checks: {endpoints}.",
         ["CWE-639"], ["V4.2 Operation Level Access Control"], 4, ["object_level_authz"],
         lambda e: "{" in e.path and not _public_path(e.path), scope="endpoint"),
    Rule("API-03", "T", "File-upload operations",
         "Multipart upload operations need type/size validation and malware scanning: {endpoints}.",
         ["CWE-434"], ["V12.1 File Upload"], 3, ["secure_upload"],
         lambda e: any("multipart" in ct for ct in e.content_types), scope="endpoint"),
    Rule("API-04", "S", "Unsigned webhook / callback endpoints",
         "Callback operations without a declared security scheme must verify HMAC signatures: {endpoints}.",
         ["CWE-345"], ["V10.3 Application Integrity"], 4, ["webhook_signature"],
         lambda e: any(k in e.path.lower() for k in ("webhook", "callback", "notify", "ipn")) and not e.secured,
         scope="endpoint", impact=5),
    Rule("API-05", "S", "Authentication / OTP endpoints need anti-automation",
         "Login, OTP and password-reset operations are brute-force targets: {endpoints}.",
         ["CWE-307"], ["V2.2 General Authenticator Security"], 3, ["rate_limiting", "account_lockout"],
         lambda e: any(k in e.path.lower() for k in ("login", "otp", "verify", "reset", "signin", "token")), scope="endpoint",
         impact=4),
    Rule("API-06", "E", "Administrative API operations",
         "Admin operations exposed on the public API need server-side role checks and MFA-backed sessions: {endpoints}.",
         ["CWE-285"], ["V4.1 General Access Control Design"], 2, ["rbac", "mfa"],
         lambda e: "/admin" in e.path.lower(), scope="endpoint"),
]


def _public_path(path: str) -> bool:
    p = path.lower()
    return any(k in p for k in ("/login", "/register", "/signup", "/health", "/otp", "/webhook", "/callback",
                                "/catalog", "/products", "/public", "/password/reset", "/auth/"))


def _has_admin(a: Architecture) -> bool:
    return any(c.type == "admin_panel" for c in a.components)


def _writes_to_store(c: Component, a: Architecture) -> bool:
    ids = {x.id for x in a.components if x.type in ("database",)}
    return any(f.source == c.id and f.target in ids for f in a.flows)


def all_rules() -> list[Rule]:
    return COMPONENT_RULES + SYSTEM_RULES + FLOW_RULES + ENDPOINT_RULES


def rule_by_id(rid: str) -> Rule | None:
    return next((r for r in all_rules() if r.id == rid), None)


def top10_for(cwes: list[str]) -> list[str]:
    out = []
    for cwe in cwes:
        k = CWE_TO_TOP10.get(cwe)
        if k and TOP10[k] not in out:
            out.append(TOP10[k])
    return out or [TOP10["A04"]]
