"""nmap: ポート・サービス検出。"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import Finding
from .base import RunContext, Runner

# インターネットや社内に公開されているべきでないことが多いサービス
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    2375: "Docker API（非TLS）",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

PROFILE_ARGS = {
    "passive": ["-sT", "-Pn", "-T2", "--top-ports", "100", "-sV", "--version-light"],
    "standard": ["-sT", "-Pn", "-T3", "--top-ports", "1000", "-sV"],
    "active": ["-sT", "-Pn", "-T3", "-p-", "-sV", "--script", "default and safe"],
}


class NmapRunner(Runner):
    name = "nmap"
    binary = "nmap"
    image = "instrumentisto/nmap:latest"

    def build_command(self, ctx: RunContext) -> list[str]:
        rps = ctx.decision.rate_limit.rps
        args = [*PROFILE_ARGS[ctx.profile], "--max-rate", str(rps), "-oX", "-", ctx.target.host]
        return self.wrap(args, ctx)

    def parse(self, stdout: str, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        if not stdout.strip():
            return findings
        root = ET.fromstring(stdout)
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else ctx.target.host
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid", "0"))
                proto = port.get("protocol", "tcp")
                svc = port.find("service")
                svc_name = svc.get("name", "") if svc is not None else ""
                product = " ".join(
                    filter(
                        None, [svc.get("product"), svc.get("version")] if svc is not None else []
                    )
                )
                location = f"{ctx.target.host}:{portid}/{proto}"
                desc = f"{addr} {portid}/{proto} {svc_name} {product}".strip()
                findings.append(
                    Finding(
                        tool=self.name,
                        rule_id=f"open-port-{proto}-{portid}",
                        title=f"開放ポート {portid}/{proto} ({svc_name or 'unknown'})",
                        severity="info",
                        target=ctx.decision.target,
                        location=location,
                        evidence=desc,
                    )
                )
                if portid in RISKY_PORTS:
                    findings.append(
                        Finding(
                            tool=self.name,
                            rule_id=f"risky-service-{portid}",
                            title=f"{RISKY_PORTS[portid]} が公開されています",
                            severity="medium",
                            target=ctx.decision.target,
                            location=location,
                            evidence=desc,
                            remediation="不要であれば停止し、必要な場合は接続元を限定してください。",
                        )
                    )
                for script in port.findall("script"):
                    sid = script.get("id", "")
                    if "VULNERABLE" in (script.get("output") or ""):
                        findings.append(
                            Finding(
                                tool=self.name,
                                rule_id=f"nse-{sid}",
                                title=f"NSE {sid} が脆弱性を検出",
                                severity="high",
                                target=ctx.decision.target,
                                location=location,
                                evidence=(script.get("output") or "")[:2000],
                            )
                        )
        return findings
