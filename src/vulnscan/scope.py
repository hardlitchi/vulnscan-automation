"""スコープ定義の読み込みと、診断実行前の許可判定（スコープガード）。

診断は必ず ScopeGuard.authorize() を通してから実行する。ここで許可されない対象には
どのスキャナも起動しない。
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, time
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import yaml

PROFILES = ("passive", "standard", "active")
_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

Resolver = Callable[[str], list[str]]


class ScopeError(ValueError):
    """スコープ定義ファイルの不備。"""


@dataclass(frozen=True)
class RateLimit:
    rps: int = 10
    concurrency: int = 5


@dataclass(frozen=True)
class TimeWindow:
    """例: "Mon-Fri 22:00-06:00"。終了が開始より前なら日付をまたぐ。"""

    days: frozenset[int]
    start: time
    end: time

    @classmethod
    def parse(cls, text: str) -> TimeWindow:
        try:
            days_part, times_part = text.split()
            start_s, end_s = times_part.split("-")
            start = time.fromisoformat(start_s)
            end = time.fromisoformat(end_s)
        except ValueError as e:
            raise ScopeError(f"time_window の形式が不正です: {text!r}") from e
        days: set[int] = set()
        for chunk in days_part.split(","):
            if "-" in chunk:
                a, b = chunk.split("-")
                ia, ib = _day_index(a), _day_index(b)
                i = ia
                while True:
                    days.add(i)
                    if i == ib:
                        break
                    i = (i + 1) % 7
            else:
                days.add(_day_index(chunk))
        return cls(frozenset(days), start, end)

    def contains(self, now: datetime) -> bool:
        t = now.time()
        today = now.weekday()
        if self.start < self.end:
            return today in self.days and self.start <= t < self.end
        # 日付をまたぐ窓: 開始日の夜、または翌日の早朝
        yesterday = (today - 1) % 7
        return (today in self.days and t >= self.start) or (yesterday in self.days and t < self.end)


def _day_index(name: str) -> int:
    try:
        return _DAYS.index(name.strip().capitalize()[:3])
    except ValueError as e:
        raise ScopeError(f"曜日が不正です: {name!r}") from e


@dataclass(frozen=True)
class Authorization:
    id: str
    approved_by: str
    valid_from: date
    valid_until: date
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    domains: tuple[str, ...]
    urls: tuple[str, ...]
    exclusions: tuple[str, ...]
    allowed_profiles: tuple[str, ...]
    time_window: TimeWindow | None
    rate_limit: RateLimit
    verify_dns: bool = True


@dataclass(frozen=True)
class Scope:
    owner: str
    timezone: ZoneInfo
    authorizations: tuple[Authorization, ...]
    kill_switch_file: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> Scope:
        if not data.get("owner"):
            raise ScopeError("owner（責任者）は必須です")
        auths_raw = data.get("authorizations") or []
        if not auths_raw:
            raise ScopeError("authorizations が 1 件もありません")
        seen: set[str] = set()
        auths = []
        for raw in auths_raw:
            a = _parse_authorization(raw)
            if a.id in seen:
                raise ScopeError(f"authorization id が重複しています: {a.id}")
            seen.add(a.id)
            auths.append(a)
        ks = data.get("kill_switch_file")
        return cls(
            owner=str(data["owner"]),
            timezone=ZoneInfo(data.get("timezone", "Asia/Tokyo")),
            authorizations=tuple(auths),
            kill_switch_file=Path(ks) if ks else None,
        )


def _parse_authorization(raw: dict) -> Authorization:
    for key in ("id", "approved_by", "valid_from", "valid_until", "targets"):
        if not raw.get(key):
            raise ScopeError(f"authorization に {key} がありません: {raw.get('id', '?')}")
    aid = str(raw["id"])
    targets = raw["targets"] or {}
    try:
        cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in targets.get("cidrs", []))
    except ValueError as e:
        raise ScopeError(f"{aid}: CIDR が不正です: {e}") from e
    urls = tuple(str(u) for u in targets.get("urls", []))
    for u in urls:
        if urlsplit(u).scheme not in ("http", "https"):
            raise ScopeError(f"{aid}: URL は http(s) で指定してください: {u}")
    domains = tuple(str(d).lower() for d in targets.get("domains", []))
    if not (cidrs or urls or domains):
        raise ScopeError(f"{aid}: targets が空です")
    profiles = tuple(raw.get("allowed_profiles", ["passive"]))
    for p in profiles:
        if p not in PROFILES:
            raise ScopeError(f"{aid}: 未知のプロファイルです: {p}")
    valid_from = _as_date(raw["valid_from"], aid)
    valid_until = _as_date(raw["valid_until"], aid)
    if valid_until < valid_from:
        raise ScopeError(f"{aid}: valid_until が valid_from より前です")
    tw = raw.get("time_window")
    rl = raw.get("rate_limit") or {}
    return Authorization(
        id=aid,
        approved_by=str(raw["approved_by"]),
        valid_from=valid_from,
        valid_until=valid_until,
        cidrs=cidrs,
        domains=domains,
        urls=urls,
        exclusions=tuple(str(x) for x in raw.get("exclusions", [])),
        allowed_profiles=profiles,
        time_window=TimeWindow.parse(tw) if tw else None,
        rate_limit=RateLimit(int(rl.get("rps", 10)), int(rl.get("concurrency", 5))),
        verify_dns=bool(raw.get("verify_dns", True)),
    )


def _as_date(v, aid: str) -> date:
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v))
    except ValueError as e:
        raise ScopeError(f"{aid}: 日付が不正です: {v}") from e


@dataclass(frozen=True)
class Target:
    """診断対象。raw は URL・ホスト名・IP のいずれか。"""

    raw: str
    host: str
    url: str | None

    @classmethod
    def parse(cls, raw: str) -> Target:
        raw = raw.strip()
        if "://" in raw:
            parts = urlsplit(raw)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"対象 URL が不正です: {raw}")
            return cls(raw, parts.hostname.lower(), raw)
        return cls(raw, raw.lower().strip("[]"), None)

    @property
    def is_ip(self) -> bool:
        return _as_ip(self.host) is not None


@dataclass
class Decision:
    allowed: bool
    target: str
    profile: str
    reasons: list[str] = field(default_factory=list)
    authorization: Authorization | None = None
    resolved_ips: list[str] = field(default_factory=list)

    @property
    def rate_limit(self) -> RateLimit:
        return self.authorization.rate_limit if self.authorization else RateLimit()


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({i[4][0] for i in infos})


def _as_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


class ScopeGuard:
    def __init__(
        self,
        scope: Scope,
        resolver: Resolver = default_resolver,
        clock: Callable[[], datetime] | None = None,
    ):
        self.scope = scope
        self.resolver = resolver
        self.clock = clock or (lambda: datetime.now(scope.timezone))

    def kill_switch_active(self) -> bool:
        if os.environ.get("VULNSCAN_KILL") == "1":
            return True
        return bool(self.scope.kill_switch_file and self.scope.kill_switch_file.exists())

    def authorize(self, raw_target: str, profile: str) -> Decision:
        """対象とプロファイルが許可されているかを判定する。最初に全条件を満たした承認を採用する。"""
        decision = Decision(False, raw_target, profile)
        if profile not in PROFILES:
            decision.reasons.append(f"未知のプロファイルです: {profile}")
            return decision
        if self.kill_switch_active():
            decision.reasons.append("キルスイッチが有効なため全診断を停止しています")
            return decision
        try:
            target = Target.parse(raw_target)
        except ValueError as e:
            decision.reasons.append(str(e))
            return decision

        resolved: list[str] | None = None
        now = self.clock()
        for auth in self.scope.authorizations:
            problems = self._check(auth, target, profile, now)
            if problems is None:
                continue  # この承認の対象外
            if not problems and auth.verify_dns and not target.is_ip and auth.cidrs:
                if resolved is None:
                    try:
                        resolved = self.resolver(target.host)
                    except OSError as e:
                        problems.append(f"名前解決に失敗しました: {target.host} ({e})")
                        resolved = []
                decision.resolved_ips = resolved
                outside = [ip for ip in resolved if not _ip_in(ip, auth.cidrs)]
                if not resolved and not problems:
                    problems.append(f"{target.host} の IP アドレスを取得できません")
                if outside:
                    problems.append(
                        f"{target.host} の解決先 {', '.join(outside)} が承認済み CIDR の外です"
                    )
                excluded_ips = [ip for ip in resolved if self._ip_excluded(auth, ip)]
                if excluded_ips:
                    problems.append(f"解決先 {', '.join(excluded_ips)} が除外対象です")
            if problems:
                decision.reasons.extend(f"[{auth.id}] {p}" for p in problems)
                continue
            decision.allowed = True
            decision.authorization = auth
            decision.reasons = [f"{auth.id}（承認者: {auth.approved_by}）により許可"]
            return decision

        if not decision.reasons:
            decision.reasons.append("どの承認のスコープにも含まれていません")
        return decision

    def _check(
        self, auth: Authorization, target: Target, profile: str, now: datetime
    ) -> list[str] | None:
        """対象がこの承認に含まれなければ None、含まれれば満たしていない条件の一覧を返す。"""
        if not self._in_targets(auth, target):
            return None
        problems: list[str] = []
        if self._excluded(auth, target):
            problems.append("除外対象に含まれています")
        today = now.date()
        if not (auth.valid_from <= today <= auth.valid_until):
            problems.append(f"承認期間外です（{auth.valid_from}〜{auth.valid_until}）")
        if profile not in auth.allowed_profiles:
            problems.append(
                f"プロファイル {profile} は許可されていません（許可: {', '.join(auth.allowed_profiles)}）"
            )
        if auth.time_window and not auth.time_window.contains(now):
            problems.append("実行可能な時間帯の外です")
        return problems

    @staticmethod
    def _in_targets(auth: Authorization, target: Target) -> bool:
        if target.url:
            if any(_url_within(target.url, u) for u in auth.urls):
                return True
        if any(_host_matches(target.host, d) for d in auth.domains):
            return True
        ip = _as_ip(target.host)
        return bool(ip and _ip_in(str(ip), auth.cidrs))

    @staticmethod
    def _excluded(auth: Authorization, target: Target) -> bool:
        for ex in auth.exclusions:
            if "://" in ex:
                if target.url and _url_within(target.url, ex):
                    return True
            elif _ip_or_net(ex) is not None:
                ip = _as_ip(target.host)
                if ip and ip in _ip_or_net(ex):
                    return True
            elif _host_matches(target.host, ex.lower()):
                return True
        return False

    @staticmethod
    def _ip_excluded(auth: Authorization, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any((n := _ip_or_net(ex)) is not None and addr in n for ex in auth.exclusions)

    def allows_url(self, decision: Decision, url: str) -> bool:
        """スキャン中に見つかった URL（リンク・リダイレクト先）が同じ承認の範囲内かを判定する。"""
        if not decision.allowed or decision.authorization is None:
            return False
        auth = decision.authorization
        try:
            t = Target.parse(url)
        except ValueError:
            return False
        return self._in_targets(auth, t) and not self._excluded(auth, t)


def _ip_or_net(s: str):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _ip_in(ip: str, nets) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        # *.example.com はサブドメインのみ（example.com 自体は含まない）
        return host.endswith(pattern[1:]) and fnmatch.fnmatchcase(host, pattern)
    return host == pattern


def _url_within(url: str, base: str) -> bool:
    u, b = urlsplit(url), urlsplit(base)
    if u.scheme != b.scheme or (u.hostname or "").lower() != (b.hostname or "").lower():
        return False
    if (u.port or _default_port(u.scheme)) != (b.port or _default_port(b.scheme)):
        return False
    base_path = b.path or "/"
    path = u.path or "/"
    if base_path.endswith("/"):
        return path.startswith(base_path) or path + "/" == base_path
    return path == base_path or path.startswith(base_path + "/")


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def iter_scope_targets(scope: Scope) -> list[str]:
    """--all 用。スコープに明示された URL とドメイン（ワイルドカード以外）を返す。"""
    out: list[str] = []
    for a in scope.authorizations:
        out.extend(a.urls)
        out.extend(d for d in a.domains if not d.startswith("*."))
    return list(dict.fromkeys(out))


__all__ = [
    "PROFILES",
    "Authorization",
    "Decision",
    "RateLimit",
    "Scope",
    "ScopeError",
    "ScopeGuard",
    "Target",
    "TimeWindow",
    "iter_scope_targets",
]
