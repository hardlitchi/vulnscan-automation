import json
from pathlib import Path

import pytest
from conftest import WED_NIGHT  # noqa: F401

from vulnscan.runners import RunContext
from vulnscan.runners.nmap import NmapRunner
from vulnscan.runners.nuclei import NucleiRunner
from vulnscan.runners.zap import ZapRunner, parse_report

FIX = Path(__file__).parent / "fixtures"


def ctx(guard, target, tmp_path, profile="standard", docker=False):
    d = guard.authorize(target, profile)
    assert d.allowed, d.reasons
    return RunContext(d, tmp_path, use_docker=docker)


def test_nmap_command_uses_rate_limit(guard, tmp_path):
    cmd = NmapRunner().build_command(ctx(guard, "https://app.example.com/", tmp_path))
    assert cmd[0] == "nmap"
    assert cmd[cmd.index("--max-rate") + 1] == "7"
    assert cmd[-1] == "app.example.com"


def test_nmap_docker_command(guard, tmp_path):
    cmd = NmapRunner().build_command(ctx(guard, "10.0.10.5", tmp_path, docker=True))
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "instrumentisto/nmap:7.98" in cmd


def test_nmap_parse(guard, tmp_path):
    c = ctx(guard, "10.0.10.5", tmp_path)
    findings = NmapRunner().parse((FIX / "nmap.xml").read_text(), c)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["open-port-tcp-443", "open-port-tcp-6379", "risky-service-6379"]
    risky = next(f for f in findings if f.rule_id == "risky-service-6379")
    assert risky.severity == "medium"
    assert "Redis" in risky.title


def test_nuclei_command_excludes_intrusive(guard, tmp_path):
    cmd = NucleiRunner().build_command(ctx(guard, "https://app.example.com/", tmp_path))
    assert cmd[cmd.index("-u") + 1] == "https://app.example.com/"
    assert "intrusive" in cmd[cmd.index("-etags") + 1]
    assert cmd[cmd.index("-c") + 1] == "3"


def test_nuclei_parse(guard, tmp_path):
    c = ctx(guard, "https://app.example.com/", tmp_path)
    findings = NucleiRunner().parse((FIX / "nuclei.jsonl").read_text(), c)
    assert len(findings) == 2
    crit = findings[0]
    assert crit.severity == "critical"
    assert crit.cve == ["CVE-2021-41773"]
    assert crit.cvss == 9.8
    assert crit.evidence == "root:x:0:0"
    assert findings[1].rule_id == "tech-detect:nginx"


def test_zap_skips_non_url(guard, tmp_path):
    res = ZapRunner().run(ctx(guard, "10.0.10.5", tmp_path), dry_run=True)
    assert res.skipped and not res.command


def test_zap_baseline_vs_full(guard, tmp_path):
    cmd = ZapRunner().build_command(ctx(guard, "https://app.example.com/", tmp_path))
    assert "zap-baseline.py" in cmd and "zap-full-scan.py" not in cmd


def test_zap_parse_dedupes_instances():
    report = json.loads((FIX / "zap.json").read_text())
    findings = parse_report(report, "https://app.example.com/")
    csp = [f for f in findings if f.rule_id == "zap-10038-1"]
    assert sorted(f.location for f in csp) == [
        "https://app.example.com/",
        "https://app.example.com/login",
    ]
    assert csp[0].severity == "medium"
    assert csp[0].description == "CSP is missing."
    assert "CWE-693" in csp[0].references
    ts = next(f for f in findings if f.rule_id == "zap-10096")
    assert ts.severity == "info"
    assert not any(r.startswith("CWE") for r in ts.references)


def test_run_reports_missing_binary(guard, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    res = NmapRunner().run(ctx(guard, "10.0.10.5", tmp_path))
    assert res.error and "見つかりません" in res.error


def _login_scope(tmp_path, **login):
    import copy

    import yaml as y
    from conftest import SCOPE

    from vulnscan.scope import Scope, ScopeGuard

    data = copy.deepcopy(SCOPE)
    a = data["authorizations"][0]
    a["time_window"] = None
    a["login"] = {
        "login_url": "https://app.example.com/login",
        "username": "tester",
        "password_env": "VULNSCAN_TEST_PW",
        **login,
    }
    p = tmp_path / "s.yaml"
    p.write_text(y.safe_dump(data, allow_unicode=True))
    from conftest import fake_resolver

    return ScopeGuard(
        Scope.load(p),
        resolver=fake_resolver({"app.example.com": ["10.0.10.5"]}),
        clock=lambda: WED_NIGHT,
    )


def test_zap_login_builds_autorun_command(tmp_path):
    from vulnscan.runners.zap import PLAN_NAME, ZapRunner

    g = _login_scope(tmp_path)
    d = g.authorize("https://app.example.com/", "standard")
    cmd = ZapRunner().build_command(RunContext(d, tmp_path))
    assert "-autorun" in cmd and f"/zap/wrk/{PLAN_NAME}" in cmd
    assert cmd[cmd.index("-e") + 1] == "VULNSCAN_TEST_PW"  # 値ではなく変数名
    assert "VULNSCAN_TEST_PW" in cmd and "secretpw" not in " ".join(cmd)


def test_zap_login_plan_contents(tmp_path):
    from vulnscan.runners.zap_plan import build_plan

    g = _login_scope(
        tmp_path, logged_in_regex="ログアウト", username_field="email", password_field="pass"
    )
    login = g.scope.authorizations[0].login
    plan, envs = build_plan("https://app.example.com/", login, "active", "zap-report.json", 10)
    assert envs == ["VULNSCAN_TEST_PW"]
    assert "${VULNSCAN_TEST_PW}" in plan  # パスワードは参照のみ
    assert "email={%username%}&pass={%password%}" in plan
    assert "activeScan" in plan and "loggedInRegex" in plan
    import yaml as y

    doc = y.safe_load(plan)
    assert doc["env"]["contexts"][0]["users"][0]["credentials"]["username"] == "tester"


def test_zap_login_requires_password_env(tmp_path, monkeypatch):
    from vulnscan.runners.zap import ZapRunner

    monkeypatch.delenv("VULNSCAN_TEST_PW", raising=False)
    g = _login_scope(tmp_path)
    d = g.authorize("https://app.example.com/", "standard")
    res = ZapRunner().run(RunContext(d, tmp_path / "w"))
    assert res.error and "VULNSCAN_TEST_PW" in res.error


def test_scope_rejects_inline_password(tmp_path):
    import copy

    from conftest import SCOPE

    from vulnscan.scope import Scope, ScopeError

    data = copy.deepcopy(SCOPE)
    data["authorizations"][0]["login"] = {
        "login_url": "https://app.example.com/login",
        "username": "u",
        "password_env": "X",
        "password": "secret",
    }
    with pytest.raises(ScopeError, match="パスワードを直接書かない"):
        Scope.from_dict(data)


def test_scope_rejects_out_of_scope_login_url(tmp_path):
    import copy

    from conftest import SCOPE

    from vulnscan.scope import Scope, ScopeError

    data = copy.deepcopy(SCOPE)
    data["authorizations"][0]["login"] = {
        "login_url": "https://evil.example.net/login",
        "username": "u",
        "password_env": "X",
    }
    with pytest.raises(ScopeError, match="範囲外"):
        Scope.from_dict(data)
