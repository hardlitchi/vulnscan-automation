"""内蔵 webcheck ランナーのテスト。ネットワークは使わず、fetch を差し替えて検証する。"""

from __future__ import annotations

from conftest import WED_NIGHT  # noqa: F401

from vulnscan.runners import RUNNERS, RunContext
from vulnscan.runners.webcheck import HttpResponse, WebCheckRunner


def _ctx(guard, target, tmp_path, profile="standard"):
    d = guard.authorize(target, profile)
    assert d.allowed, d.reasons
    return RunContext(d, tmp_path, timeout=5, url_allowed=lambda u, d=d: guard.allows_url(d, u))


def _resp(url, status=200, headers=None, body="", cookies=None):
    hdrs = list((headers or {}).items())
    hdrs += [("Set-Cookie", c) for c in (cookies or [])]
    return HttpResponse(url, status, hdrs, body)


def make_fetch(pages: dict[str, HttpResponse]):
    """URL -> HttpResponse の表で応答する fetch。未登録 URL は 404。"""
    calls: list[str] = []

    def fetch(url, timeout):  # noqa: ANN001
        calls.append(url)
        return pages.get(url, HttpResponse(url, 404, [], "not found"))

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def test_registered_in_runners():
    assert "webcheck" in RUNNERS and RUNNERS["webcheck"] is WebCheckRunner


def test_skips_non_url_target(guard, tmp_path):
    res = WebCheckRunner().run(_ctx(guard, "10.0.10.5", tmp_path), dry_run=True)
    assert res.skipped and not res.command


def test_dry_run_sets_command_no_requests(guard, tmp_path):
    fetch = make_fetch({})
    res = WebCheckRunner(fetch=fetch).run(
        _ctx(guard, "https://app.example.com/", tmp_path), dry_run=True
    )
    assert res.skipped == "dry-run"
    assert res.command[0] == "(内蔵) webcheck"
    assert fetch.calls == []  # dry-run では一切リクエストしない


def test_passive_flags_missing_headers_and_cookies(guard, tmp_path):
    url = "https://app.example.com/"
    fetch = make_fetch(
        {
            url: _resp(
                url,
                headers={"Content-Type": "text/html", "Server": "nginx/1.18.0"},
                cookies=["session=abc; Path=/"],
                body="<html><body>hi</body></html>",
            )
        }
    )
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path, profile="passive"))
    assert res.error is None
    ids = {f.rule_id for f in res.findings}
    assert "hsts-missing" in ids
    assert "csp-missing" in ids
    assert "clickjacking-protection-missing" in ids
    assert "x-content-type-options-missing" in ids
    assert "version-disclosure:server" in ids
    # https なのに Secure/HttpOnly/SameSite が無い Cookie
    assert "cookie-secure-missing:session" in ids
    assert "cookie-httponly-missing:session" in ids
    assert "cookie-samesite-missing:session" in ids
    # passive では派生 URL を叩かない（1 リクエストのみ）
    assert fetch.calls == [url]


def test_good_headers_produce_no_header_findings(guard, tmp_path):
    url = "https://app.example.com/"
    fetch = make_fetch(
        {
            url: _resp(
                url,
                headers={
                    "Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=63072000",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
                cookies=["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"],
                body="<html></html>",
            )
        }
    )
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path, profile="passive"))
    ids = {f.rule_id for f in res.findings}
    for rid in (
        "hsts-missing",
        "csp-missing",
        "clickjacking-protection-missing",
        "x-content-type-options-missing",
        "cookie-secure-missing:session",
    ):
        assert rid not in ids


def test_cleartext_http_flagged(guard, tmp_path):
    # web.stg.example.com は *.stg.example.com で許可、time_window 内
    url = "http://web.stg.example.com/"
    fetch = make_fetch(
        {url: _resp(url, headers={"Content-Type": "text/html"}, body="<html></html>")}
    )
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path, profile="passive"))
    assert "cleartext-transport" in {f.rule_id for f in res.findings}


def test_unreachable_target_is_error(guard, tmp_path):
    url = "https://app.example.com/"
    fetch = make_fetch({url: HttpResponse(url, 0, [], "", error="connection refused")})
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path))
    assert res.error and "接続できません" in res.error


def test_directory_listing_and_csrf_and_mixed_content(guard, tmp_path):
    url = "https://app.example.com/"
    body = (
        "<html><head><title>Index of /files</title></head><body>"
        '<img src="http://cdn.example.net/a.png">'
        '<form method="post" action="/save"><input type="text" name="q"></form>'
        "</body></html>"
    )
    fetch = make_fetch({url: _resp(url, headers={"Content-Type": "text/html"}, body=body)})
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path, profile="passive"))
    ids = {f.rule_id for f in res.findings}
    assert "directory-listing" in ids
    assert "mixed-content" in ids
    assert "form-without-csrf-token" in ids


def test_csrf_token_present_suppresses_finding(guard, tmp_path):
    url = "https://app.example.com/"
    body = (
        '<html><form method="post"><input type="hidden" name="csrf_token" value="x">'
        '<input type="text" name="q"></form></html>'
    )
    fetch = make_fetch({url: _resp(url, headers={"Content-Type": "text/html"}, body=body)})
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, url, tmp_path, profile="passive"))
    assert "form-without-csrf-token" not in {f.rule_id for f in res.findings}


def test_sensitive_file_exposed_requires_signature(guard, tmp_path):
    base = "https://app.example.com/"
    git = "https://app.example.com/.git/config"
    fetch = make_fetch(
        {
            base: _resp(base, headers={"Content-Type": "text/html"}, body="<html></html>"),
            git: _resp(
                git,
                headers={"Content-Type": "text/plain"},
                body="[core]\n\trepositoryformatversion = 0",
            ),
        }
    )
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, base, tmp_path, profile="standard"))
    hits = [f for f in res.findings if f.rule_id == "sensitive-file-exposed"]
    assert len(hits) == 1 and hits[0].location == git and hits[0].severity == "high"


def test_sensitive_file_signature_mismatch_not_reported(guard, tmp_path):
    base = "https://app.example.com/"
    git = "https://app.example.com/.git/config"
    # 200 だが中身は署名に一致しない（SPA の index.html が返るケース）
    fetch = make_fetch(
        {
            base: _resp(base, headers={"Content-Type": "text/html"}, body="<html></html>"),
            git: _resp(git, headers={"Content-Type": "text/html"}, body="<html>404-ish</html>"),
        }
    )
    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, base, tmp_path, profile="standard"))
    assert not [f for f in res.findings if f.rule_id == "sensitive-file-exposed"]


def test_out_of_scope_paths_not_requested(guard, tmp_path):
    # in_scope が拒否した派生 URL は一切叩かない（スコープガードと同じ判定）。
    base = "https://app.example.com/"
    d = guard.authorize(base, "standard")
    assert d.allowed, d.reasons
    # base 以外はすべてスコープ外とみなす url_allowed を注入する
    ctx = RunContext(d, tmp_path, timeout=5, url_allowed=lambda u: u == base)
    fetch = make_fetch(
        {base: _resp(base, headers={"Content-Type": "text/html"}, body="<html></html>")}
    )
    WebCheckRunner(fetch=fetch).run(ctx)
    assert fetch.calls == [base]  # 派生 GET は in_scope で全て弾かれた


def test_reflected_parameter_detected(guard, tmp_path):
    base = "https://app.example.com/search?q=hello"
    reflected = "https://app.example.com/search?q=vulnscanREF0Z9"

    def fetch(url, timeout):  # noqa: ANN001
        if url == base:
            return _resp(url, headers={"Content-Type": "text/html"}, body="<html>hello</html>")
        if "vulnscanREF0Z9" in url:
            return _resp(
                url, headers={"Content-Type": "text/html"}, body="<html>vulnscanREF0Z9</html>"
            )
        return _resp(url, headers={"Content-Type": "text/html"}, body="<html>ok</html>")

    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, base, tmp_path, profile="standard"))
    refl = [f for f in res.findings if f.rule_id.startswith("reflected-parameter")]
    assert refl and refl[0].rule_id == "reflected-parameter:q"
    assert refl[0].location == reflected


def test_sql_error_reflected_detected(guard, tmp_path):
    base = "https://app.example.com/item?id=5"

    def fetch(url, timeout):  # noqa: ANN001
        if url.endswith("id=5"):
            return _resp(url, headers={"Content-Type": "text/html"}, body="<html>item</html>")
        if "%27" in url or "'" in url:  # シングルクオートを足したプローブ
            return _resp(
                url,
                headers={"Content-Type": "text/html"},
                body="You have an error in your SQL syntax near ''' at line 1",
            )
        return _resp(url, headers={"Content-Type": "text/html"}, body="<html>ok</html>")

    res = WebCheckRunner(fetch=fetch).run(_ctx(guard, base, tmp_path, profile="standard"))
    sqli = [f for f in res.findings if f.rule_id.startswith("sql-error-reflected")]
    assert sqli and sqli[0].rule_id == "sql-error-reflected:id"
    assert sqli[0].severity == "high"


def test_passive_profile_does_no_active_probes(guard, tmp_path):
    base = "https://app.example.com/search?q=hello"
    fetch = make_fetch(
        {base: _resp(base, headers={"Content-Type": "text/html"}, body="<html>hi</html>")}
    )
    WebCheckRunner(fetch=fetch).run(_ctx(guard, base, tmp_path, profile="passive"))
    assert fetch.calls == [base]  # 受動のみ: 追加リクエストなし
