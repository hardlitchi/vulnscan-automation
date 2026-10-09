import json
import secrets
import time

from test_web import fake_nuclei, make_client  # noqa: F401 (fixture)

from vulnscan.web.api import sign_request

SECRET = "x" * 32


def call(client, method, path, body=None, *, secret=SECRET, ts=None, nonce=None, sig=None):
    raw = b"" if body is None else json.dumps(body).encode()
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(16)
    headers = {
        "X-Vulnscan-Timestamp": ts,
        "X-Vulnscan-Nonce": nonce,
        "X-Vulnscan-Signature": sig or sign_request(secret, ts, nonce, method, path, raw),
        "Content-Type": "application/json",
    }
    return client.request(method, path, content=raw, headers=headers)


def scan_body(**kw):
    body = {
        "target": "https://app.example.com/",
        "profile": "standard",
        "tools": ["nuclei"],
        "confirm": True,
        "actor": "ta",
    }
    body.update(kw)
    return body


def test_api_disabled_without_secret(tmp_path):
    client, _, _ = make_client(tmp_path)
    r = call(client, "GET", "/api/status")
    assert r.status_code == 503
    assert r.json()["code"] == "API_DISABLED"


def test_signature_checks(tmp_path):
    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    assert call(client, "GET", "/api/status").status_code == 200
    assert call(client, "GET", "/api/status", secret="y" * 32).json()["code"] == "INVALID_SIGNATURE"
    old = int(time.time()) - 3600
    assert call(client, "GET", "/api/status", ts=old).json()["code"] == "SIGNATURE_EXPIRED"
    r = client.get("/api/status")
    assert r.status_code == 401 and r.json()["code"] == "INVALID_SIGNATURE"
    # 同じ nonce は 2 回目を拒否する
    nonce = secrets.token_urlsafe(16)
    assert call(client, "GET", "/api/status", nonce=nonce).status_code == 200
    assert call(client, "GET", "/api/status", nonce=nonce).json()["code"] == "REPLAYED"
    # 署名はパスに紐づく（/api/status の署名で /api/targets は叩けない）
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    sig = sign_request(SECRET, ts, nonce, "GET", "/api/status", b"")
    r = call(client, "GET", "/api/targets", ts=ts, nonce=nonce, sig=sig)
    assert r.json()["code"] == "INVALID_SIGNATURE"


def test_webhook_style_signature_is_rejected(tmp_path):
    """結果送信（webhook）の署名形式では API を叩けない。"""
    from vulnscan.notify import sign

    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    raw = json.dumps(scan_body()).encode()
    ts = str(int(time.time()))
    r = client.post(
        "/api/scans",
        content=raw,
        headers={
            "X-Vulnscan-Timestamp": ts,
            "X-Vulnscan-Nonce": secrets.token_urlsafe(16),
            "X-Vulnscan-Signature": sign(SECRET, ts, raw),
        },
    )
    assert r.status_code == 401


def test_targets(tmp_path):
    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    r = call(client, "GET", "/api/targets")
    assert r.status_code == 200
    items = {t["target"]: t for t in r.json()["targets"]}
    app = items["https://app.example.com/"]
    assert app["allowed_profiles"] == ["passive", "standard"]
    assert app["resolved_ips"] == ["10.0.10.5"]


def test_start_scan_and_poll(tmp_path, fake_nuclei):  # noqa: F811
    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    r = call(client, "POST", "/api/scans", scan_body())
    assert r.status_code == 202, r.text
    job = r.json()
    assert job["status"] == "done"
    assert fake_nuclei == ["https://app.example.com/"]
    r = call(client, "GET", f"/api/scans/{job['id']}")
    assert r.json()["run_ids"] == [1]
    log = (tmp_path / "audit.log").read_text()
    assert '"actor": "ta (api)"' in log
    assert call(client, "GET", "/api/scans/nope").json()["code"] == "NOT_FOUND"


def test_start_scan_refusals(tmp_path, fake_nuclei):  # noqa: F811
    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    r = call(client, "POST", "/api/scans", scan_body(confirm=False))
    assert r.json()["code"] == "CONFIRM_REQUIRED"
    # scope.yaml に明記されていない対象（CIDR 内の任意 IP も含む）は選べない
    r = call(client, "POST", "/api/scans", scan_body(target="10.0.10.9"))
    assert r.status_code == 403 and r.json()["code"] == "OUT_OF_SCOPE"
    r = call(client, "POST", "/api/scans", scan_body(target="https://example.org/"))
    assert r.json()["code"] == "OUT_OF_SCOPE"
    # 許可されていないプロファイル
    r = call(client, "POST", "/api/scans", scan_body(profile="active"))
    assert r.status_code == 403
    assert any("active" in x for x in r.json()["reasons"])
    r = call(client, "POST", "/api/scans", scan_body(tools=["rm"]))
    assert r.json()["code"] == "INVALID_REQUEST"
    # キルスイッチ中は止まる
    (tmp_path / "stop").write_text("x")
    r = call(client, "POST", "/api/scans", scan_body())
    assert r.status_code == 403
    assert any("キルスイッチ" in x for x in r.json()["reasons"])
    assert fake_nuclei == []


def test_api_404_is_json(tmp_path):
    client, _, _ = make_client(tmp_path, api_secret=SECRET)
    r = client.get("/api/nothing")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"
