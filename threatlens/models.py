"""Core data model for ThreatLens.

Everything the agent produces is built from these plain dataclasses so the
state can be serialised to JSON, inspected in tests, and rendered to reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Component types understood by the knowledge base.
COMPONENT_TYPES = {
    "user": "External entity (human actor)",
    "web_frontend": "Web front end (SPA / server-rendered)",
    "mobile_app": "Mobile app (Android / iOS)",
    "api": "Backend API",
    "service": "Internal service / worker",
    "admin_panel": "Back-office / admin dashboard",
    "database": "Database",
    "object_storage": "Object / file storage",
    "cache": "Cache",
    "queue": "Message queue",
    "identity_provider": "Identity provider (SSO / OAuth)",
    "third_party": "Third-party service",
}

ZONES = ["internet", "dmz", "internal", "data", "third_party"]

ZONE_LABELS = {
    "internet": "Internet (untrusted)",
    "dmz": "DMZ / public edge",
    "internal": "Internal application zone",
    "data": "Data zone",
    "third_party": "Third-party providers",
}

# Data classification -> impact (1..5)
DATA_SENSITIVITY = {
    "phi": 5,           # health / medical records
    "payment": 5,       # card / wallet / payment tokens
    "credentials": 5,   # passwords, tokens, OTPs
    "secrets": 5,       # API keys, signing keys
    "national_id": 4,   # Egyptian national ID, Saudi ID / Iqama
    "financial": 4,     # salaries, IBANs, balances
    "pii": 4,           # names, phones, addresses, emails
    "internal": 2,
    "public": 1,
}

DATA_LABELS = {
    "phi": "Health data (PHI)",
    "payment": "Payment data",
    "credentials": "Credentials / tokens",
    "secrets": "Secrets / keys",
    "national_id": "National ID / Iqama",
    "financial": "Financial data",
    "pii": "Personal data (PII)",
    "internal": "Internal business data",
    "public": "Public data",
}

STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


@dataclass
class Component:
    id: str
    name: str
    type: str
    zone: str = "internal"
    tech: str = ""
    data: list[str] = field(default_factory=list)
    auth: str = "none"            # none | password | session | jwt | oauth | sso | api_key | mtls | mfa
    internet_facing: bool = False
    controls: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)  # file_upload, url_fetch, webhooks_in, otp, ...
    category: str = ""            # for third parties: payment, messaging, shipping, government, ...
    notes: str = ""

    def has(self, *controls: str) -> bool:
        return any(c in self.controls for c in controls)

    def feature(self, *feats: str) -> bool:
        return any(f in self.features for f in feats)

    @property
    def sensitivity(self) -> int:
        return max([DATA_SENSITIVITY.get(d, 2) for d in self.data] or [2])

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity >= 4


@dataclass
class Flow:
    id: str
    source: str
    target: str
    protocol: str = "https"
    data: list[str] = field(default_factory=list)
    auth: str = "none"
    description: str = ""
    controls: list[str] = field(default_factory=list)

    @property
    def sensitivity(self) -> int:
        return max([DATA_SENSITIVITY.get(d, 2) for d in self.data] or [2])


@dataclass
class Endpoint:
    method: str
    path: str
    summary: str = ""
    secured: bool = False
    content_types: list[str] = field(default_factory=list)
    component: str = ""


@dataclass
class Architecture:
    name: str
    description: str = ""
    industry: str = ""
    region: str = ""
    users: str = ""
    compliance: list[str] = field(default_factory=list)
    global_controls: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    source_kind: str = "yaml"

    def component(self, cid: str) -> Component | None:
        return next((c for c in self.components if c.id == cid), None)

    def has_global(self, *controls: str) -> bool:
        return any(c in self.global_controls for c in controls)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    stride: str
    target: str               # component id, flow id or "system"
    target_kind: str          # component | flow | endpoint | system
    description: str
    cwe: list[str] = field(default_factory=list)
    owasp_top10: list[str] = field(default_factory=list)
    asvs: list[str] = field(default_factory=list)
    likelihood: int = 3
    impact: int = 3
    risk: int = 0
    severity: str = ""
    mitigations: list[str] = field(default_factory=list)
    evidence: str = ""
    source: str = "kb"        # kb | llm
    mapped: bool = False
    scored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationItem:
    key: str
    title: str
    detail: str
    effort_days: float
    owner: str
    phase: str
    priority: int
    findings: list[str] = field(default_factory=list)
    risk_reduced: int = 0
