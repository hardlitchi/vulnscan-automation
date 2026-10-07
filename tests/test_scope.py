from datetime import datetime

import pytest
from conftest import JST, SCOPE, fake_resolver

from vulnscan.scope import Scope, ScopeError, ScopeGuard, TimeWindow, iter_scope_targets


def test_allows_listed_url(guard):
    d = guard.authorize("https://app.example.com/login", "standard")
    assert d.allowed, d.reasons
    assert d.authorization.id == "AUTH-1"
    assert d.rate_limit.rps == 7
    assert d.resolved_ips == ["10.0.10.5"]


def test_allows_ip_in_cidr(guard):
    assert guard.authorize("10.0.10.20", "passive").allowed


def test_denies_unlisted_target(guard):
    d = guard.authorize("https://example.org/", "passive")
    assert not d.allowed
    assert "許可リスト（scope.yaml）に登録されていない対象です" in d.reasons[0]


def test_denies_ip_outside_cidr(guard):
    assert not guard.authorize("10.0.11.1", "passive").allowed


def test_denies_excluded_ip_and_url(guard):
    assert not guard.authorize("10.0.10.1", "passive").allowed
    d = guard.authorize("https://app.example.com/admin/users", "passive")
    assert not d.allowed
    assert any("除外" in r for r in d.reasons)


def test_denies_excluded_hostname(guard):
    assert not guard.authorize("db.stg.example.com", "passive").allowed


def test_wildcard_matches_subdomain_only(guard):
    assert guard.authorize("web.stg.example.com", "passive").allowed
    assert not guard.authorize("stg.example.com", "passive").allowed
    assert not guard.authorize("web.stg.example.com.evil.net", "passive").allowed


def test_denies_when_dns_points_outside_cidr(guard):
    d = guard.authorize("evil.stg.example.com", "passive")
    assert not d.allowed
    assert any("203.0.113.9" in r for r in d.reasons)


def test_denies_when_dns_points_to_excluded_ip(guard):
    assert not guard.authorize("rtr.stg.example.com", "passive").allowed


def test_denies_when_dns_fails(guard):
    assert not guard.authorize("unknown.stg.example.com", "passive").allowed


def test_denies_profile_not_allowed(guard):
    d = guard.authorize("https://app.example.com/", "active")
    assert not d.allowed
    assert any("active" in r for r in d.reasons)


def test_denies_outside_time_window(scope):
    noon = ScopeGuard(
        scope,
        resolver=fake_resolver({"app.example.com": ["10.0.10.5"]}),
        clock=lambda: datetime(2026, 10, 7, 12, 0, tzinfo=JST),
    )
    assert not noon.authorize("https://app.example.com/", "passive").allowed


def test_denies_outside_validity(scope):
    later = ScopeGuard(
        scope, resolver=fake_resolver({}), clock=lambda: datetime(2027, 4, 1, 23, 0, tzinfo=JST)
    )
    d = later.authorize("10.0.10.20", "passive")
    assert not d.allowed
    assert any("承認期間外" in r for r in d.reasons)


def test_kill_switch_env(guard, monkeypatch):
    monkeypatch.setenv("VULNSCAN_KILL", "1")
    d = guard.authorize("10.0.10.20", "passive")
    assert not d.allowed
    assert "キルスイッチ" in d.reasons[0]


def test_kill_switch_file(tmp_path):
    stop = tmp_path / "stop"
    scope = Scope.from_dict({**SCOPE, "kill_switch_file": str(stop)})
    g = ScopeGuard(
        scope, resolver=fake_resolver({}), clock=lambda: datetime(2026, 10, 7, 23, 0, tzinfo=JST)
    )
    assert g.authorize("10.0.10.20", "passive").allowed
    stop.touch()
    assert not g.authorize("10.0.10.20", "passive").allowed


def test_rejects_non_http_url(guard):
    assert not guard.authorize("ftp://app.example.com/", "passive").allowed


def test_url_prefix_does_not_match_other_port_or_scheme(scope):
    data = {
        **SCOPE,
        "authorizations": [
            {
                **SCOPE["authorizations"][0],
                "targets": {"urls": ["https://app.example.com/"]},
                "time_window": None,
            }
        ],
    }
    g = ScopeGuard(
        Scope.from_dict(data),
        resolver=fake_resolver({}),
        clock=lambda: datetime(2026, 10, 7, 12, 0, tzinfo=JST),
    )
    assert g.authorize("https://app.example.com/x", "passive").allowed
    assert not g.authorize("http://app.example.com/x", "passive").allowed
    assert not g.authorize("https://app.example.com:8443/x", "passive").allowed


def test_allows_url_for_discovered_links(guard):
    d = guard.authorize("https://app.example.com/", "passive")
    assert guard.allows_url(d, "https://app.example.com/search?q=1")
    assert not guard.allows_url(d, "https://app.example.com/admin/x")
    assert not guard.allows_url(d, "https://other.example.net/")


@pytest.mark.parametrize(
    "when,expected",
    [
        (datetime(2026, 10, 7, 22, 0), True),  # 水 22:00
        (datetime(2026, 10, 8, 5, 59), True),  # 木 05:59（水の夜から継続）
        (datetime(2026, 10, 8, 6, 0), False),
        (datetime(2026, 10, 10, 23, 0), False),  # 土 23:00
        (datetime(2026, 10, 10, 3, 0), True),  # 土 03:00（金の夜から継続）
        (datetime(2026, 10, 12, 3, 0), False),  # 月 03:00（日の夜は対象外）
    ],
)
def test_time_window_overnight(when, expected):
    assert TimeWindow.parse("Mon-Fri 22:00-06:00").contains(when) is expected


def test_time_window_same_day():
    tw = TimeWindow.parse("Sat,Sun 09:00-17:00")
    assert tw.contains(datetime(2026, 10, 10, 9, 0))
    assert not tw.contains(datetime(2026, 10, 9, 10, 0))


@pytest.mark.parametrize(
    "mutate,msg",
    [
        (lambda d: d.pop("owner"), "owner"),
        (lambda d: d["authorizations"][0]["targets"].update(cidrs=["bad"]), "CIDR"),
        (lambda d: d["authorizations"][0].update(allowed_profiles=["nuke"]), "プロファイル"),
        (lambda d: d["authorizations"][0].update(valid_until="2026-01-01"), "valid_until"),
        (lambda d: d["authorizations"].append(dict(d["authorizations"][0])), "重複"),
    ],
)
def test_invalid_scope(mutate, msg):
    import copy

    data = copy.deepcopy(SCOPE)
    mutate(data)
    with pytest.raises(ScopeError, match=msg):
        Scope.from_dict(data)


def test_iter_scope_targets(scope):
    assert iter_scope_targets(scope) == ["https://app.example.com/", "app.example.com"]


def test_example_scope_file_is_valid():
    from pathlib import Path

    Scope.load(Path(__file__).parent.parent / "scope.example.yaml")
