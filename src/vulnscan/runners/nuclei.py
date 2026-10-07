"""nuclei: 既知脆弱性・設定不備のテンプレート診断。"""

from __future__ import annotations

import json

from ..models import Finding
from .base import RunContext, Runner

PROFILE_ARGS = {
    "passive": ["-tags", "tech,exposure,misconfig,ssl", "-etags", "intrusive,dos,fuzz,bruteforce"],
    "standard": ["-etags", "intrusive,dos,fuzz,bruteforce"],
    "active": ["-etags", "dos"],
}


class NucleiRunner(Runner):
    name = "nuclei"
    binary = "nuclei"
    image = "projectdiscovery/nuclei:latest"

    def build_command(self, ctx: RunContext) -> list[str]:
        t = ctx.target
        rl = ctx.decision.rate_limit
        args = [
            "-u",
            t.url or t.host,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-rl",
            str(rl.rps),
            "-c",
            str(rl.concurrency),
            *PROFILE_ARGS[ctx.profile],
        ]
        return self.wrap(args, ctx)

    def parse(self, stdout: str, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            info = r.get("info") or {}
            cls = info.get("classification") or {}
            rule_id = r.get("template-id", "unknown")
            if r.get("matcher-name"):
                rule_id += f":{r['matcher-name']}"
            evidence = r.get("extracted-results") or r.get("matcher-name") or ""
            if isinstance(evidence, list):
                evidence = ", ".join(map(str, evidence))
            refs = info.get("reference") or []
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=rule_id,
                    title=info.get("name", rule_id),
                    severity=info.get("severity", "info"),
                    target=ctx.decision.target,
                    location=r.get("matched-at") or r.get("host") or ctx.decision.target,
                    evidence=str(evidence)[:2000],
                    description=(info.get("description") or "").strip(),
                    remediation=(info.get("remediation") or "").strip(),
                    cve=[c.upper() for c in (cls.get("cve-id") or []) if c],
                    cvss=cls.get("cvss-score"),
                    references=refs if isinstance(refs, list) else [str(refs)],
                )
            )
        return findings
