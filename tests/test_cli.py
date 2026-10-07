import copy
import json
from pathlib import Path

import yaml
from conftest import SCOPE

from vulnscan import cli
from vulnscan.models import Finding
from vulnscan.runners import RunResult


def write_scope(tmp_path, **auth_overrides):
    data = copy.deepcopy(SCOPE)
    data["authorizations"][0].update(time_window=None, verify_dns=False, **auth_overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


def test_scope_validate(tmp_path, capsys):
    assert cli.main(["scope", "validate", "-s", str(write_scope(tmp_path))]) == 0
    assert "AUTH-1" in capsys.readouterr().out


def test_scope_check_denied(tmp_path):
    p = write_scope(tmp_path)
    assert cli.main(["scope", "check", "-s", str(p), "-t", "https://example.org/"]) == 2


def test_scan_denied_target_runs_no_tool(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("subprocess.run", lambda *a, **k: called.append(a))
    p = write_scope(tmp_path)
    rc = cli.main(
        [
            "scan",
            "-s",
            str(p),
            "-t",
            "https://example.org/",
            "--db",
            str(tmp_path / "db"),
            "--out",
            str(tmp_path / "out"),
            "--audit-log",
            str(tmp_path / "audit.log"),
        ]
    )
    assert rc == 2
    assert called == []
    log = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert log[0]["event"] == "scope_decision" and log[0]["allowed"] is False
    report = next((tmp_path / "out").glob("*/report.md")).read_text()
    assert "スコープ外のため診断していません" in report


def test_scan_end_to_end_with_fake_runner(tmp_path, monkeypatch):
    def fake_run(self, ctx, dry_run=False):
        findings = [
            Finding(
                tool=self.name,
                rule_id="r1",
                title="SQLi",
                severity="high",
                target=ctx.decision.target,
                location="https://app.example.com/q",
            ),
            Finding(
                tool=self.name,
                rule_id="r2",
                title="off",
                severity="high",
                target=ctx.decision.target,
                location="https://evil.example.net/",
            ),
        ]
        return RunResult(self.name, ["fake"], findings=findings)

    monkeypatch.setattr("vulnscan.runners.nuclei.NucleiRunner.run", fake_run)
    p = write_scope(tmp_path)
    args = [
        "scan",
        "-s",
        str(p),
        "-t",
        "https://app.example.com/",
        "--tools",
        "nuclei",
        "--db",
        str(tmp_path / "db"),
        "--out",
        str(tmp_path / "out"),
        "--audit-log",
        str(tmp_path / "audit.log"),
        "--fail-on",
        "high",
        "--suppressions",
        str(tmp_path / "none.yaml"),
    ]
    assert cli.main(args) == 1  # 新規 high があるので失敗終了
    out = sorted((tmp_path / "out").glob("*/report.json"))[-1]
    data = json.loads(out.read_text())["targets"][0]
    assert [x["rule_id"] for x in data["new"]] == ["r1"]  # スコープ外の結果は破棄
    md = out.with_name("report.md").read_text()
    assert "スコープ外として破棄した結果" in md

    # 2 回目は継続扱いなので --fail-on に該当しない
    import time

    time.sleep(1.1)
    assert cli.main(args) == 0


def test_scan_dry_run_prints_commands(tmp_path, capsys):
    p = write_scope(tmp_path)
    rc = cli.main(
        [
            "scan",
            "-s",
            str(p),
            "-t",
            "https://app.example.com/",
            "--dry-run",
            "--audit-log",
            str(tmp_path / "audit.log"),
            "--db",
            str(tmp_path / "db"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "$ nmap" in out and "$ nuclei" in out and "zap-baseline.py" in out
    assert not Path(tmp_path / "db").exists()
