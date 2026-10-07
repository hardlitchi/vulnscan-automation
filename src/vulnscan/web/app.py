"""FastAPI による Web 画面。

診断の開始は必ず ScopeGuard の判定を通す（engine.execute_scan と同じ経路）。
画面から scope.yaml を編集する機能はあえて持たない（承認はレビューを経て管理者が行う）。
"""

import csv
import io
import ipaddress
import secrets
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..engine import ScanOptions, execute_scan
from ..models import SEVERITIES, Finding, severity_rank
from ..runners import RUNNERS
from ..scope import PROFILES, Scope, ScopeError, ScopeGuard, iter_scope_targets
from ..store import Store
from ..suppressions import Suppression, load_suppressions, split_suppressed
from . import labels
from .jobs import Busy, Job, JobManager

HERE = Path(__file__).parent


@dataclass
class WebSettings:
    scope_path: Path
    db: Path = Path("vulnscan.db")
    out: Path = Path("reports")
    audit_log: Path = Path("audit.log")
    suppressions: Path = Path("suppressions.yaml")
    use_docker: bool = False
    timeout: int = 3600
    username: str = "admin"
    password: str | None = None
    run_in_background: bool = True


def create_app(settings: WebSettings, guard_factory=ScopeGuard) -> FastAPI:
    app = FastAPI(title="脆弱性診断", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    jobs = JobManager()
    csrf_token = secrets.token_urlsafe(32)
    basic = HTTPBasic(auto_error=False)

    def current_user(
        creds: Annotated[HTTPBasicCredentials | None, Depends(basic)],
    ) -> str | None:
        if not settings.password:
            return None
        ok = (
            creds is not None
            and secrets.compare_digest(creds.username.encode(), settings.username.encode())
            and secrets.compare_digest(creds.password.encode(), settings.password.encode())
        )
        if not ok:
            raise HTTPException(
                status_code=401,
                detail="ログインが必要です",
                headers={"WWW-Authenticate": 'Basic realm="vulnscan"'},
            )
        return creds.username

    User = Annotated[str | None, Depends(current_user)]

    def check_csrf(token: str) -> None:
        if not secrets.compare_digest(token.encode(), csrf_token.encode()):
            raise HTTPException(
                status_code=400, detail="画面を開き直してからもう一度操作してください"
            )

    @app.exception_handler(HTTPException)
    async def html_error(request: Request, exc: HTTPException):
        # 画面を使う人向けに JSON ではなく HTML で理由を表示する
        resp = templates.TemplateResponse(
            request,
            "error.html",
            {"detail": exc.detail, "status": exc.status_code, "user": None, "labels": labels},
            status_code=exc.status_code,
        )
        for k, v in (exc.headers or {}).items():
            resp.headers[k] = v
        return resp

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def load_scope() -> tuple[Scope | None, str | None]:
        try:
            return Scope.load(settings.scope_path), None
        except (OSError, ScopeError) as e:
            return None, str(e)

    def load_rules() -> tuple[list[Suppression], str | None]:
        try:
            return load_suppressions(settings.suppressions), None
        except ValueError as e:
            return [], str(e)

    def render(request: Request, name: str, user: str | None, **ctx) -> HTMLResponse:
        scope, scope_error = load_scope()
        guard = guard_factory(scope) if scope else None
        base = {
            "user": user,
            "csrf": csrf_token,
            "labels": labels,
            "severities": SEVERITIES,
            "scope": scope,
            "scope_error": scope_error,
            "kill_active": bool(guard and guard.kill_switch_active()),
            "kill_file": scope.kill_switch_file if scope else None,
            "current_job": jobs.current(),
            "tz": scope.timezone if scope else None,
        }
        return templates.TemplateResponse(request, name, {**base, **ctx})

    def fmt_time(value, tz=None) -> str:
        if not value:
            return "-"
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        if tz is not None:
            dt = dt.astimezone(tz)
        return dt.strftime("%Y/%m/%d %H:%M")

    templates.env.filters["jtime"] = fmt_time

    def store() -> Store:
        return Store(settings.db)

    # ---- ホーム ----
    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, user: User):
        s = store()
        try:
            runs = s.list_runs(limit=5)
            open_findings = s.open_findings()
        finally:
            s.close()
        rules, _ = load_rules()
        visible, _ = split_suppressed(open_findings, rules)
        counts = Counter(f.severity for f in visible)
        by_target = Counter(f.target for f in visible if f.severity != "info")
        return render(
            request,
            "home.html",
            user,
            runs=runs,
            counts=counts,
            by_target=by_target.most_common(),
        )

    # ---- 診断の開始 ----
    def scan_form(request: Request, user, **ctx) -> HTMLResponse:
        scope, _ = load_scope()
        choices = iter_scope_targets(scope) if scope else []
        defaults = {"target": "", "target_other": "", "profile": "standard", "tools": list(RUNNERS)}
        return render(
            request,
            "scan_new.html",
            user,
            choices=choices,
            profiles=PROFILES,
            tools=list(RUNNERS),
            form={**defaults, **ctx.pop("form", {})},
            **ctx,
        )

    @app.get("/scan/new", response_class=HTMLResponse)
    def scan_new(request: Request, user: User, target: str = ""):
        return scan_form(request, user, form={"target": target})

    @app.post("/scan", response_class=HTMLResponse)
    def scan_start(
        request: Request,
        user: User,
        csrf: Annotated[str, Form()],
        target: Annotated[str, Form()] = "",
        target_other: Annotated[str, Form()] = "",
        profile: Annotated[str, Form()] = "standard",
        tools: Annotated[list[str] | None, Form()] = None,
        confirm: Annotated[str, Form()] = "",
    ):
        check_csrf(csrf)
        form = {
            "target": target,
            "target_other": target_other,
            "profile": profile,
            "tools": tools or [],
        }
        raw = (target_other if target == "__other__" else target).strip()
        errors = []
        if not raw:
            errors.append("診断する対象を選んでください。")
        if profile not in PROFILES:
            errors.append("診断の種類を選んでください。")
        chosen = [t for t in (tools or []) if t in RUNNERS]
        if not chosen:
            errors.append("チェック内容を 1 つ以上選んでください。")
        if not confirm:
            errors.append("「許可を得た対象です」にチェックを入れてください。")
        if errors:
            return scan_form(request, user, form=form, errors=errors)

        scope, scope_error = load_scope()
        if scope is None:
            return scan_form(
                request,
                user,
                form=form,
                errors=[f"設定ファイルの読み込みに失敗しました: {scope_error}"],
            )
        guard = guard_factory(scope)
        decision = guard.authorize(raw, profile)
        if not decision.allowed:
            return scan_form(request, user, form=form, denied=decision)

        rules, _ = load_rules()
        opts = ScanOptions(
            profile=profile,
            tools=chosen,
            db=settings.db,
            out=settings.out,
            audit_log=settings.audit_log,
            use_docker=settings.use_docker,
            timeout=settings.timeout,
            actor=user or "local",
        )

        def work(job: Job) -> None:
            execute_scan(
                scope,
                [raw],
                opts,
                suppressions=rules,
                log=job.log.append,
                guard=guard,
                on_run_started=job.run_ids.append,
            )

        try:
            job = jobs.submit(
                raw, profile, chosen, user, work, background=settings.run_in_background
            )
        except Busy:
            return scan_form(
                request,
                user,
                form=form,
                errors=["ほかの診断が実行中です。終わってからもう一度開始してください。"],
            )
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, user: User, job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(
                404, "この診断は見つかりません（画面を再起動した場合は履歴から確認してください）"
            )
        return render(request, "job.html", user, job=job)

    # ---- 結果 ----
    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request, user: User):
        s = store()
        try:
            runs = s.list_runs(limit=200)
        finally:
            s.close()
        return render(request, "runs.html", user, runs=runs)

    def load_run(run_id: int):
        s = store()
        try:
            info = s.run_info(run_id)
            if info is None:
                raise HTTPException(404, "この診断結果は見つかりません")
            diff = s.run_diff(run_id)
            first = s.first_seen([f.fingerprint for f in diff.open])
        finally:
            s.close()
        rules, _ = load_rules()
        _, suppressed = split_suppressed(diff.open, rules)
        hidden = {f.fingerprint for f, _ in suppressed}
        return info, diff, suppressed, hidden, first

    def sort_findings(items: list[Finding]) -> list[Finding]:
        return sorted(items, key=lambda f: (severity_rank(f.severity), f.title, f.location))

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, user: User, run_id: int):
        info, diff, suppressed, hidden, first = load_run(run_id)
        new = [f for f in diff.new if f.fingerprint not in hidden]
        persisting = [f for f in diff.persisting if f.fingerprint not in hidden]
        actionable_new = sort_findings([f for f in new if f.severity != "info"])
        actionable_old = sort_findings([f for f in persisting if f.severity != "info"])
        info_items = sort_findings([f for f in new + persisting if f.severity == "info"])
        counts = Counter(f.severity for f in new + persisting)
        return render(
            request,
            "run.html",
            user,
            run=info,
            counts=counts,
            actionable_new=actionable_new,
            actionable_old=actionable_old,
            info_items=info_items,
            fixed=sort_findings(diff.fixed),
            suppressed=suppressed,
            first_seen=first,
        )

    @app.get("/runs/{run_id}/findings.csv")
    def run_csv(user: User, run_id: int):
        info, diff, suppressed, hidden, first = load_run(run_id)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "状態",
                "重大度",
                "対応の目安",
                "タイトル",
                "場所",
                "初回検出",
                "CVE",
                "対策",
                "ツール",
                "ルール",
                "ID",
            ]
        )
        rows = [("新規", f) for f in diff.new] + [("継続", f) for f in diff.persisting]
        rows += [("解消", f) for f in diff.fixed]
        for state, f in rows:
            if f.fingerprint in hidden:
                state = "対応不要として登録済み"
            sev = labels.SEVERITY[f.severity]
            w.writerow(
                [
                    state,
                    sev["label"],
                    sev["guide"],
                    f.title,
                    f.location,
                    first.get(f.fingerprint, ""),
                    " ".join(f.cve),
                    f.remediation,
                    f.tool,
                    f.rule_id,
                    f.fingerprint,
                ]
            )
        # Excel で文字化けしないよう BOM 付き UTF-8
        data = "﻿" + buf.getvalue()
        return Response(
            data,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="vulnscan-run-{run_id}.csv"'},
        )

    # ---- 対象一覧 ----
    @app.get("/targets", response_class=HTMLResponse)
    def targets_page(request: Request, user: User):
        scope, _ = load_scope()
        status = {}
        if scope:
            guard = guard_factory(scope)
            now = guard.clock()
            for a in scope.authorizations:
                problems = []
                if not (a.valid_from <= now.date() <= a.valid_until):
                    problems.append("承認期間外")
                if a.time_window and not a.time_window.contains(now):
                    problems.append("今は実行できる時間帯の外")
                status[a.id] = problems
        return render(request, "targets.html", user, status=status, days=_DAYS_JA)

    # ---- 緊急停止 ----
    @app.post("/emergency-stop")
    def emergency_stop(user: User, csrf: Annotated[str, Form()]):
        check_csrf(csrf)
        scope, _ = load_scope()
        if scope is None or scope.kill_switch_file is None:
            raise HTTPException(400, "緊急停止用のファイルが設定されていません（kill_switch_file）")
        scope.kill_switch_file.parent.mkdir(parents=True, exist_ok=True)
        scope.kill_switch_file.write_text(
            f"stopped by {user or 'local'} at {datetime.now().isoformat()}\n"
        )
        return RedirectResponse("/", status_code=303)

    @app.post("/emergency-resume")
    def emergency_resume(user: User, csrf: Annotated[str, Form()]):
        check_csrf(csrf)
        scope, _ = load_scope()
        if scope and scope.kill_switch_file and scope.kill_switch_file.exists():
            scope.kill_switch_file.unlink()
        return RedirectResponse("/", status_code=303)

    app.state.jobs = jobs
    app.state.csrf = csrf_token
    return app


_DAYS_JA = ["月", "火", "水", "木", "金", "土", "日"]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(settings: WebSettings, host: str = "127.0.0.1", port: int = 8000) -> int:
    if not _is_loopback(host) and not settings.password:
        raise ValueError(
            "自分の PC 以外からアクセスできるようにする場合は、環境変数 VULNSCAN_UI_PASSWORD で"
            "パスワードを設定してください。"
        )
    import uvicorn

    app = create_app(settings)
    print(
        f"ブラウザで http://{'localhost' if _is_loopback(host) else host}:{port}/ を開いてください"
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
