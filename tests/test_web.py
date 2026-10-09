import base64
import copy
import re

import pytest
import yaml
from conftest import SCOPE, WED_NIGHT, fake_resolver
from fastapi.testclient import TestClient

from vulnscan.models import Finding
from vulnscan.runners import RunResult
from vulnscan.scope import ScopeGuard
from vulnscan.web.app import WebSettings, _is_loopback, create_app, serve


def make_client(tmp_path, password=None, api_secret=None, **auth_overrides):
    data = copy.deepcopy(SCOPE)
    data["kill_switch_file"] = str(tmp_path / "stop")
    data["authorizations"][0].update(**auth_overrides)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    settings = WebSettings(
        scope_path=scope_path,
        db=tmp_path / "db.sqlite",
        out=tmp_path / "reports",
        audit_log=tmp_path / "audit.log",
        suppressions=tmp_path / "suppressions.yaml",
        password=password,
        run_in_background=False,
        api_secret=api_secret,
    )

    def guard_factory(scope):
        return ScopeGuard(
            scope,
            resolver=fake_resolver({"app.example.com": ["10.0.10.5"]}),
            clock=lambda: WED_NIGHT,
        )

    app = create_app(settings, guard_factory=guard_factory)
    return TestClient(app), app, settings


@pytest.fixture
def fake_nuclei(monkeypatch):
    calls = []

    def fake_run(self, ctx, dry_run=False):
        calls.append(ctx.decision.target)
        return RunResult(
            self.name,
            ["fake"],
            findings=[
                Finding(
                    tool=self.name,
                    rule_id="CVE-2021-41773",
                    title="Apache Path Traversal",
                    severity="critical",
                    target=ctx.decision.target,
                    location="https://app.example.com/cgi-bin/x",
                    description="パストラバーサル",
                    remediation="Apache を更新してください",
                    cve=["CVE-2021-41773"],
                ),
                Finding(
                    tool=self.name,
                    rule_id="tech",
                    title="nginx detected",
                    severity="info",
                    target=ctx.decision.target,
                    location="https://app.example.com/",
                ),
            ],
        )

    monkeypatch.setattr("vulnscan.runners.nuclei.NucleiRunner.run", fake_run)
    return calls


def start(client, app, **form):
    data = {
        "csrf": app.state.csrf,
        "target": "https://app.example.com/",
        "profile": "standard",
        "tools": ["nuclei"],
        "confirm": "yes",
    }
    data.update(form)
    return client.post("/scan", data=data, follow_redirects=False)


def test_home_empty(tmp_path):
    client, _, _ = make_client(tmp_path)
    r = client.get("/")
    assert r.status_code == 200
    assert "診断を始める" in r.text
    assert "まだ診断していません" in r.text
    assert r.headers["X-Frame-Options"] == "DENY"


def test_scan_form_lists_scope_targets(tmp_path):
    client, _, _ = make_client(tmp_path)
    r = client.get("/scan/new")
    assert "https://app.example.com/" in r.text
    assert "標準診断（おすすめ）" in r.text


def test_full_flow(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = start(client, app)
    assert r.status_code == 303
    job_url = r.headers["location"]
    job_page = client.get(job_url)
    assert "診断が終わりました" in job_page.text
    run_url = re.search(r'href="(/runs/\d+)"', job_page.text).group(1)

    run_page = client.get(run_url)
    assert "Apache Path Traversal" in run_page.text
    assert "Apache を更新してください" in run_page.text
    assert "今回新しく見つかった問題（1 件）" in run_page.text
    assert "参考情報（対応不要）を見る（1 件）" in run_page.text

    csv = client.get(run_url + "/findings.csv")
    assert csv.headers["content-type"].startswith("text/csv")
    body = csv.content.decode("utf-8-sig")
    assert "新規" in body and "緊急" in body

    home = client.get("/")
    assert "結果を見る" in home.text
    assert client.get("/runs").status_code == 200

    # 2 回目は「以前から残っている問題」に入る
    start(client, app)
    run2 = client.get("/runs/2")
    assert "以前から残っている問題（1 件）" in run2.text
    assert fake_nuclei == ["https://app.example.com/", "https://app.example.com/"]

    log = (tmp_path / "audit.log").read_text()
    assert '"actor": "local"' in log


def test_denied_target_does_not_scan(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = start(client, app, target="__other__", target_other="https://example.org/")
    assert r.status_code == 200
    assert "この内容では診断できません" in r.text
    assert fake_nuclei == []


def test_profile_not_allowed(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = start(client, app, profile="active")
    assert "診断の種類 active はこの対象では許可されていません" in r.text
    assert fake_nuclei == []


def test_requires_confirmation_and_target(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = start(client, app, confirm="", target="")
    assert "許可を得た対象です" in r.text
    assert "診断する対象を選んでください" in r.text
    assert fake_nuclei == []


def test_csrf_required(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = start(client, app, csrf="wrong")
    assert r.status_code == 400
    assert fake_nuclei == []


def test_emergency_stop_blocks_scans(tmp_path, fake_nuclei):
    client, app, _ = make_client(tmp_path)
    r = client.post("/emergency-stop", data={"csrf": app.state.csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert (tmp_path / "stop").exists()
    assert "緊急停止中です" in client.get("/").text
    r = start(client, app)
    assert "キルスイッチ" in r.text
    assert fake_nuclei == []
    client.post("/emergency-resume", data={"csrf": app.state.csrf})
    assert not (tmp_path / "stop").exists()


def test_targets_page(tmp_path):
    client, _, _ = make_client(tmp_path)
    r = client.get("/targets")
    assert "AUTH-1" in r.text
    assert "月火水木金曜日 22:00〜06:00" in r.text
    assert "いま診断できます" in r.text


def test_password_required_when_configured(tmp_path):
    client, _, _ = make_client(tmp_path, password="s3cret")
    assert client.get("/").status_code == 401
    token = base64.b64encode(b"admin:s3cret").decode()
    r = client.get("/", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 200
    bad = base64.b64encode(b"admin:nope").decode()
    assert client.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401


def test_refuses_public_bind_without_password(tmp_path):
    settings = WebSettings(scope_path=tmp_path / "scope.yaml")
    with pytest.raises(ValueError, match="VULNSCAN_UI_PASSWORD"):
        serve(settings, host="0.0.0.0")
    assert _is_loopback("127.0.0.1") and _is_loopback("localhost") and not _is_loopback("0.0.0.0")


def test_unknown_run_404(tmp_path):
    client, _, _ = make_client(tmp_path)
    assert client.get("/runs/999").status_code == 404


def test_errors_are_html(tmp_path):
    client, _, _ = make_client(tmp_path)
    r = client.get("/runs/999")
    assert r.headers["content-type"].startswith("text/html")
    assert "この診断結果は見つかりません" in r.text


def test_ai_toggle_hidden_when_disabled(tmp_path):
    client, _, _ = make_client(tmp_path)
    assert "AIによる探索支援" not in client.get("/scan/new").text


def test_ai_flow(tmp_path, fake_nuclei, monkeypatch):
    import json as _json

    from vulnscan.ai import AIConfig

    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    client, app, settings = make_client(tmp_path)
    settings.ai = AIConfig(provider="claude")

    def fake_ai(system, user, max_tokens):
        return _json.dumps(
            {
                "hypotheses": [
                    {
                        "title": "連番IDで他人の情報が見える恐れ",
                        "area": "authorization",
                        "severity": "high",
                        "confidence": "medium",
                        "rationale": "IDが連番",
                        "verification": "別IDでアクセス",
                        "location": "https://app.example.com/u/2",
                    }
                ]
            }
        )

    # execute_scan は engine 側で ai_complete を使う。ここでは app 経由ではなく
    # engine を直接差し替えるのではなく、provider を fake にするため monkeypatch。
    monkeypatch.setattr("vulnscan.ai.base._provider_complete", lambda c: fake_ai)

    r = client.get("/scan/new")
    assert "AIによる探索支援" in r.text
    data = {
        "csrf": app.state.csrf,
        "target": "https://app.example.com/",
        "profile": "standard",
        "tools": ["nuclei"],
        "confirm": "yes",
        "use_ai": "yes",
    }
    client.post("/scan", data=data, follow_redirects=False)
    run = client.get("/runs/1")
    assert "AIの提案" in run.text
    assert "連番IDで他人の情報が見える恐れ" in run.text
