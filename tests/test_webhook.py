import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from test_cli import write_scope

from vulnscan import cli
from vulnscan.models import Finding
from vulnscan.notify import post_webhook
from vulnscan.runners import RunResult
from vulnscan.runners.nmap import NmapRunner

SECRET = "webhook-secret-0123456789"


@pytest.fixture
def receiver():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append((dict(self.headers), body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/api/vulnscan/ingest", got
    srv.shutdown()


def verify(headers, body):
    ts = headers["X-Vulnscan-Timestamp"]
    mac = hmac.new(SECRET.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return headers["X-Vulnscan-Signature"] == "sha256=" + mac


def test_post_webhook_signs_body(receiver):
    url, got = receiver
    post_webhook(url, {"a": 1}, SECRET)
    headers, body = got[0]
    assert verify(headers, body)
    assert json.loads(body) == {"a": 1}


def test_post_webhook_rejects_short_secret(receiver):
    url, got = receiver
    with pytest.raises(ValueError):
        post_webhook(url, {}, "short")
    assert got == []


def test_scan_posts_signed_results(tmp_path, monkeypatch, receiver):
    url, got = receiver
    monkeypatch.setenv("VULNSCAN_WEBHOOK_URL", url)
    monkeypatch.setenv("VULNSCAN_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("VULNSCAN_SOURCE_IPS", "198.51.100.7, 2001:db8::7")

    def fake_run(self, ctx, dry_run=False):
        f = Finding(
            tool=self.name,
            rule_id="r1",
            title="SQLi",
            severity="high",
            target=ctx.decision.target,
            location="https://app.example.com/q",
            evidence="x" * 5000,
        )
        return RunResult(self.name, ["fake"], findings=[f])

    monkeypatch.setattr("vulnscan.runners.nuclei.NucleiRunner.run", fake_run)
    p = write_scope(tmp_path)
    args = ["scan", "-s", str(p), "-t", "https://app.example.com/", "-t", "https://example.org/"]
    args += ["--tools", "nuclei", "--db", str(tmp_path / "db"), "--out", str(tmp_path / "out")]
    args += ["--audit-log", str(tmp_path / "audit.log")]
    cli.main(args)

    headers, body = got[0]
    assert verify(headers, body)
    data = json.loads(body)
    assert data["source"] == "vulnscan" and data["version"] == 1
    assert data["scanner"]["source_ips"] == ["198.51.100.7", "2001:db8::7"]
    assert data["started_at"] <= data["finished_at"]
    allowed, denied = data["targets"]
    assert allowed["allowed"] is True and denied["allowed"] is False and denied["reasons"]
    assert [(f["rule_id"], f["change"]) for f in allowed["open"]] == [("r1", "new")]
    assert len(allowed["open"][0]["evidence"]) == 2000
    assert allowed["tools"] == [{"tool": "nuclei", "ok": True, "count": 1}]


def test_scan_without_webhook_url_sends_nothing(tmp_path, monkeypatch, receiver):
    _, got = receiver
    monkeypatch.delenv("VULNSCAN_WEBHOOK_URL", raising=False)
    p = write_scope(tmp_path)
    cli.main(
        ["scan", "-s", str(p), "-t", "https://example.org/", "--db", str(tmp_path / "db")]
        + ["--out", str(tmp_path / "out"), "--audit-log", str(tmp_path / "a.log")]
    )
    assert got == []


def test_image_is_pinned_and_overridable(monkeypatch):
    assert not NmapRunner().image_ref.endswith(":latest")
    monkeypatch.setenv("VULNSCAN_IMAGE_NMAP", "instrumentisto/nmap:7.99")
    assert NmapRunner().image_ref == "instrumentisto/nmap:7.99"
