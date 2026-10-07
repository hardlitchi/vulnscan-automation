"""誤検知・リスク受容として扱う指摘の抑制リスト。理由と期限を必須にする。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

from .models import Finding

STATUSES = ("false_positive", "accepted_risk")


@dataclass(frozen=True)
class Suppression:
    reason: str
    status: str
    expires: date
    fingerprint: str | None = None
    rule_id: str | None = None
    target: str | None = None

    def matches(self, f: Finding, today: date) -> bool:
        if today > self.expires:
            return False
        if self.fingerprint:
            return f.fingerprint == self.fingerprint
        if self.rule_id != f.rule_id:
            return False
        return self.target is None or self.target == f.target


def load_suppressions(path: str | Path | None) -> list[Suppression]:
    if not path or not Path(path).exists():
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out = []
    for i, raw in enumerate(data.get("suppressions") or []):
        if not raw.get("reason") or not raw.get("expires"):
            raise ValueError(f"suppressions[{i}]: reason と expires は必須です")
        if not (raw.get("fingerprint") or raw.get("rule_id")):
            raise ValueError(f"suppressions[{i}]: fingerprint か rule_id を指定してください")
        status = raw.get("status", "false_positive")
        if status not in STATUSES:
            raise ValueError(f"suppressions[{i}]: status は {STATUSES} のいずれかです")
        exp = raw["expires"]
        out.append(
            Suppression(
                reason=str(raw["reason"]),
                status=status,
                expires=exp if isinstance(exp, date) else date.fromisoformat(str(exp)),
                fingerprint=raw.get("fingerprint"),
                rule_id=raw.get("rule_id"),
                target=raw.get("target"),
            )
        )
    return out


def split_suppressed(
    findings: list[Finding], rules: list[Suppression], today: date | None = None
) -> tuple[list[Finding], list[tuple[Finding, Suppression]]]:
    today = today or date.today()
    kept: list[Finding] = []
    suppressed: list[tuple[Finding, Suppression]] = []
    for f in findings:
        rule = next((r for r in rules if r.matches(f, today)), None)
        if rule:
            suppressed.append((f, rule))
        else:
            kept.append(f)
    return kept, suppressed
