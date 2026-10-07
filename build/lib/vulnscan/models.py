"""各スキャナの結果を正規化した共通 Finding スキーマ。"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_ALIASES = {
    "informational": "info",
    "information": "info",
    "unknown": "info",
    "moderate": "medium",
}


def normalize_severity(value: str | None) -> str:
    v = (value or "info").strip().lower()
    v = _SEVERITY_ALIASES.get(v, v)
    return v if v in SEVERITIES else "info"


def severity_rank(severity: str) -> int:
    """critical が 0。並べ替え用。"""
    return SEVERITIES.index(normalize_severity(severity))


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    target: str
    location: str
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)

    @property
    def fingerprint(self) -> str:
        """同一の指摘を前回結果と突き合わせるための指紋。証跡の揺れに左右されない要素のみ使う。"""
        key = "\x1f".join([self.tool, self.rule_id, self.target, self.location])
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d
