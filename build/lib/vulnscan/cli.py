"""コマンドラインインターフェース。

vulnscan scope validate  -s scope.yaml
vulnscan scope check     -s scope.yaml -t https://app.example.com/ -p standard
vulnscan scan            -s scope.yaml -t https://app.example.com/ -p standard
vulnscan scan            -s scope.yaml --all -p passive --docker
vulnscan web             -s scope.yaml            # ブラウザで操作する画面
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .engine import ScanOptions, execute_scan
from .models import SEVERITIES, severity_rank
from .runners import RUNNERS
from .scope import PROFILES, Scope, ScopeError, ScopeGuard, iter_scope_targets
from .suppressions import load_suppressions

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_DENIED = 2
EXIT_CONFIG = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan", description="許可された自社資産の脆弱性診断を自動実行します"
    )
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scope", help="スコープ定義の検証・判定")
    scs = sc.add_subparsers(dest="scope_command", required=True)
    v = scs.add_parser("validate", help="scope.yaml の書式を検証する")
    v.add_argument("-s", "--scope", required=True)
    c = scs.add_parser("check", help="対象が診断可能かを判定する（スキャンはしない）")
    c.add_argument("-s", "--scope", required=True)
    c.add_argument("-t", "--target", required=True)
    c.add_argument("-p", "--profile", default="passive", choices=PROFILES)

    s = sub.add_parser("scan", help="スコープガードを通過した対象を診断する")
    s.add_argument("-s", "--scope", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", action="append", help="対象 URL / ホスト / IP（複数可）")
    g.add_argument("--all", action="store_true", help="scope.yaml の URL とドメインをすべて診断")
    s.add_argument("-p", "--profile", default="passive", choices=PROFILES)
    s.add_argument(
        "--tools", default="nmap,nuclei,zap", help=f"カンマ区切り（{', '.join(RUNNERS)}）"
    )
    s.add_argument("--db", default="vulnscan.db")
    s.add_argument("--out", default="reports", help="レポート出力ディレクトリ")
    s.add_argument("--audit-log", default="audit.log")
    s.add_argument("--suppressions", default="suppressions.yaml")
    s.add_argument("--docker", action="store_true", help="スキャナを Docker イメージで実行する")
    s.add_argument("--dry-run", action="store_true", help="判定と実行コマンドの表示のみ")
    s.add_argument("--timeout", type=int, default=3600, help="ツールごとのタイムアウト秒")
    s.add_argument(
        "--fail-on", choices=SEVERITIES, help="この重大度以上の新規指摘があれば終了コード 1"
    )
    s.add_argument(
        "--notify-min",
        default="high",
        choices=SEVERITIES,
        help="Slack 通知する重大度の下限（VULNSCAN_SLACK_WEBHOOK 設定時）",
    )
    w = sub.add_parser("web", help="ブラウザで操作する画面を起動する")
    w.add_argument("-s", "--scope", required=True)
    w.add_argument("--host", default="127.0.0.1", help="待ち受けアドレス（既定は自分の PC のみ）")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--db", default="vulnscan.db")
    w.add_argument("--out", default="reports")
    w.add_argument("--audit-log", default="audit.log")
    w.add_argument("--suppressions", default="suppressions.yaml")
    w.add_argument("--docker", action="store_true", help="スキャナを Docker イメージで実行する")
    w.add_argument("--timeout", type=int, default=3600)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "web":
        return run_web(args)
    try:
        scope = Scope.load(args.scope)
    except (OSError, ScopeError) as e:
        print(f"スコープ定義を読み込めません: {e}", file=sys.stderr)
        return EXIT_CONFIG

    if args.command == "scope":
        if args.scope_command == "validate":
            print(
                f"OK: {len(scope.authorizations)} 件の承認を読み込みました（責任者: {scope.owner}）"
            )
            for a in scope.authorizations:
                print(
                    f"  - {a.id}: {a.valid_from}〜{a.valid_until} "
                    f"profiles={','.join(a.allowed_profiles)}"
                )
            return EXIT_OK
        d = ScopeGuard(scope).authorize(args.target, args.profile)
        print(("許可" if d.allowed else "拒否") + f": {args.target} ({args.profile})")
        for r in d.reasons:
            print(f"  - {r}")
        return EXIT_OK if d.allowed else EXIT_DENIED

    return run_scan(args, scope)


def run_scan(args, scope: Scope) -> int:
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in RUNNERS]
    if unknown:
        print(f"未知のツールです: {', '.join(unknown)}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        rules = load_suppressions(args.suppressions)
    except ValueError as e:
        print(f"抑制リストが不正です: {e}", file=sys.stderr)
        return EXIT_CONFIG

    targets = iter_scope_targets(scope) if args.all else args.target
    opts = ScanOptions(
        profile=args.profile,
        tools=tools,
        db=args.db,
        out=args.out,
        audit_log=args.audit_log,
        use_docker=args.docker,
        dry_run=args.dry_run,
        timeout=args.timeout,
        notify_min=args.notify_min,
    )
    outcome = execute_scan(scope, targets, opts, suppressions=rules)

    if args.fail_on and not args.dry_run:
        limit = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) <= limit for r in outcome.reports for f in r.visible_new):
            return EXIT_FINDINGS
    return EXIT_DENIED if outcome.any_denied else EXIT_OK


def run_web(args) -> int:
    try:
        from .web.app import WebSettings, serve
    except ImportError:
        print(
            "Web 画面には追加パッケージが必要です: pip install -e '.[web]'",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    settings = WebSettings(
        scope_path=Path(args.scope),
        db=Path(args.db),
        out=Path(args.out),
        audit_log=Path(args.audit_log),
        suppressions=Path(args.suppressions),
        use_docker=args.docker,
        timeout=args.timeout,
        username=os.environ.get("VULNSCAN_UI_USER", "admin"),
        password=os.environ.get("VULNSCAN_UI_PASSWORD"),
    )
    try:
        return serve(settings, host=args.host, port=args.port)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
