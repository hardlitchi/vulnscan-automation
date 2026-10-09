"""MeshConsole などの管理画面から診断を起動するための署名付き API（/api/*）。

人が使う画面（Basic 認証・CSRF）とは別に、共有シークレットの HMAC 署名で認証する。
シークレットは結果送信（webhook）と同じ VULNSCAN_WEBHOOK_SECRET を使う（設定は 1 つで済む）。
署名の対象は webhook と区別できる形にしてあり、webhook の本文を流用して API を叩くことはできない:

    X-Vulnscan-Timestamp: <UNIX 秒>
    X-Vulnscan-Nonce:     <毎回ランダムな 16〜64 文字>
    X-Vulnscan-Signature: sha256=HMAC-SHA256(secret, "<timestamp>.<nonce>.<METHOD>.<path>.<本文>")

時刻ずれは ±5 分まで。同じ nonce は 10 分間受け付けない（再送攻撃の防止）。
診断の開始は画面と同じ経路（ScopeGuard の判定 → JobManager）を通るため、
scope.yaml で承認された対象・プロファイル・時間帯以外は API からも実行できない。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..runners import RUNNERS
from ..scope import PROFILES, Scope, iter_scope_targets
from .jobs import Busy, Job, JobManager

MAX_SKEW_SEC = 5 * 60
NONCE_TTL_SEC = 10 * 60
MIN_SECRET_LEN = 16
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
LOG_TAIL = 200


def sign_request(
    secret: str, timestamp: str, nonce: str, method: str, path: str, body: bytes
) -> str:
    msg = f"{timestamp}.{nonce}.{method.upper()}.{path}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra


class NonceCache:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, nonce: str, now: float) -> bool:
        """初めて見た nonce なら True。期限切れのものはついでに捨てる。"""
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + NONCE_TTL_SEC
            return True


def _scope_targets(scope: Scope) -> list[str]:
    """画面・API で選べる対象。URL・ドメインに加え、単一ホストの CIDR（/32・/128）は IP として出す。"""
    out = list(iter_scope_targets(scope))
    for a in scope.authorizations:
        for net in a.cidrs:
            if net.num_addresses == 1:
                out.append(str(net.network_address))
    return list(dict.fromkeys(out))


def job_view(job: Job) -> dict:
    return {
        "id": job.id,
        "target": job.target,
        "profile": job.profile,
        "tools": job.tools,
        "actor": job.actor,
        "status": job.status,
        "error": job.error,
        "run_ids": job.run_ids,
        "log": job.log[-LOG_TAIL:],
        "created_at": job.created_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


def register_api(
    app: FastAPI,
    *,
    secret: str | None,
    jobs: JobManager,
    load_scope: Callable[[], tuple[Scope | None, str | None]],
    guard_factory: Callable,
    launch: Callable[..., Job],
    clock: Callable[[], float] = time.time,
) -> None:
    nonces = NonceCache()

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError):
        return JSONResponse(
            {"error": exc.message, "code": exc.code, **exc.extra}, status_code=exc.status
        )

    async def verify(request: Request) -> bytes:
        if not secret:
            raise ApiError(
                503,
                "API_DISABLED",
                "診断の API は無効です（VULNSCAN_REMOTE_SCAN=true と VULNSCAN_WEBHOOK_SECRET を設定してください）",
            )
        body = await request.body()
        ts = request.headers.get("x-vulnscan-timestamp", "")
        nonce = request.headers.get("x-vulnscan-nonce", "")
        sig = request.headers.get("x-vulnscan-signature", "")
        if not ts or not nonce or not sig or not NONCE_RE.match(nonce):
            raise ApiError(401, "INVALID_SIGNATURE", "署名がありません")
        try:
            ts_num = int(ts)
        except ValueError:
            raise ApiError(401, "SIGNATURE_EXPIRED", "署名の時刻が不正です") from None
        now = clock()
        if abs(now - ts_num) > MAX_SKEW_SEC:
            raise ApiError(
                401, "SIGNATURE_EXPIRED", "署名の時刻がずれています（両方の時計を確認してください）"
            )
        expected = sign_request(secret, ts, nonce, request.method, request.url.path, body)
        if not hmac.compare_digest(sig.encode(), expected.encode()):
            raise ApiError(401, "INVALID_SIGNATURE", "署名が一致しません")
        if not nonces.add(nonce, now):
            raise ApiError(401, "REPLAYED", "同じ要求を既に受け付けています")
        return body

    def require_scope() -> Scope:
        scope, err = load_scope()
        if scope is None:
            raise ApiError(503, "SCOPE_ERROR", f"scope.yaml を読み込めません: {err}")
        return scope

    @app.get("/api/status")
    async def api_status(request: Request):
        await verify(request)
        scope, err = load_scope()
        guard = guard_factory(scope) if scope else None
        cur = jobs.current()
        return {
            "ok": scope is not None,
            "scope_error": err,
            "kill_switch": bool(guard and guard.kill_switch_active()),
            "current_job": job_view(cur) if cur else None,
            "tools": list(RUNNERS),
            "profiles": list(PROFILES),
        }

    @app.get("/api/targets")
    async def api_targets(request: Request):
        await verify(request)
        scope = require_scope()
        guard = guard_factory(scope)
        items = []
        for t in _scope_targets(scope):
            allowed: list[str] = []
            reasons: list[str] = []
            resolved: list[str] = []
            for p in PROFILES:
                d = guard.authorize(t, p)
                resolved = resolved or d.resolved_ips
                if d.allowed:
                    allowed.append(p)
                elif not reasons:
                    reasons = d.reasons
            items.append(
                {
                    "target": t,
                    "allowed_profiles": allowed,
                    "reasons": [] if allowed else reasons,
                    "resolved_ips": resolved,
                }
            )
        return {"targets": items, "kill_switch": guard.kill_switch_active()}

    @app.post("/api/scans", status_code=202)
    async def api_scan_start(request: Request):
        body = await verify(request)
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            raise ApiError(400, "INVALID_REQUEST", "本文が JSON ではありません") from None
        if not isinstance(data, dict):
            raise ApiError(400, "INVALID_REQUEST", "本文が JSON オブジェクトではありません")
        target = str(data.get("target") or "").strip()
        profile = str(data.get("profile") or "passive")
        tools = data.get("tools") or list(RUNNERS)
        actor = str(data.get("actor") or "api")[:64]
        if not target or len(target) > 2048:
            raise ApiError(400, "INVALID_REQUEST", "診断する対象を指定してください")
        if profile not in PROFILES:
            raise ApiError(400, "INVALID_REQUEST", f"未知のプロファイルです: {profile}")
        if not isinstance(tools, list) or not all(t in RUNNERS for t in tools) or not tools:
            raise ApiError(400, "INVALID_REQUEST", "チェック内容（tools）が正しくありません")
        if data.get("confirm") is not True:
            raise ApiError(
                400, "CONFIRM_REQUIRED", "許可を得た対象であることの確認（confirm）が必要です"
            )
        scope = require_scope()
        # API から選べるのは scope.yaml に明記された対象だけ（任意の IP を CIDR 内から指定させない）
        if target not in _scope_targets(scope):
            raise ApiError(403, "OUT_OF_SCOPE", "scope.yaml に記載された対象ではありません")
        guard = guard_factory(scope)
        decision = guard.authorize(target, profile)
        if not decision.allowed:
            raise ApiError(
                403, "OUT_OF_SCOPE", "この対象は今は診断できません", reasons=decision.reasons
            )
        try:
            job = launch(scope, guard, target, profile, list(tools), f"{actor} (api)")
        except Busy:
            cur = jobs.current()
            raise ApiError(
                409, "BUSY", "ほかの診断が実行中です", current_job=job_view(cur) if cur else None
            ) from None
        return job_view(job)

    @app.get("/api/scans/{job_id}")
    async def api_scan_get(request: Request, job_id: str):
        await verify(request)
        job = jobs.get(job_id)
        if job is None:
            raise ApiError(
                404,
                "NOT_FOUND",
                "この診断は見つかりません（vulnscan を再起動した可能性があります）",
            )
        return job_view(job)

    # /api/* の 404 も JSON で返す（画面向けの HTML エラーにしない）
    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def api_not_found(rest: str):
        raise ApiError(404, "NOT_FOUND", "見つかりません")
