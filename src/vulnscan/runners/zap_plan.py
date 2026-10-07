"""ログインが必要な Web アプリ向けの ZAP Automation Framework プラン生成。

パスワードはプランファイルに書かず、環境変数名への参照（${ENV}）として埋め込む。
実行時に docker の -e で同名の変数を渡し、ZAP 側が置換する。
"""

from __future__ import annotations

import re

import yaml

from ..scope import LoginConfig


def build_plan(
    base_url: str, login: LoginConfig, profile: str, report_name: str, rps: int
) -> tuple[str, list[str]]:
    """(プランYAML, docker に渡す環境変数名の一覧) を返す。"""
    include = [_escape(base_url) + ".*"]
    exclude = [_escape(base_url.rstrip("/")) + re.escape(p) + ".*" for p in login.logout_paths]

    context = {
        "name": "target",
        "urls": [base_url],
        "includePaths": include,
        "excludePaths": exclude,
        "sessionManagement": {"method": "cookie"},
        "users": [
            {
                "name": "user",
                "credentials": {
                    "username": login.username,
                    "password": "${" + login.password_env + "}",
                },
            }
        ],
    }
    verification = {"method": "poll" if login.logged_in_regex else "autodetect"}
    if login.logged_in_regex:
        verification = {
            "method": "response",
            "loggedInRegex": login.logged_in_regex,
            "loggedOutRegex": login.logged_out_regex or "",
        }

    if login.method == "browser":
        context["authentication"] = {
            "method": "browser",
            "parameters": {
                "loginPageUrl": login.login_url,
                "loginPageWait": 5,
                "browserId": "firefox-headless",
            },
            "verification": verification,
        }
    else:
        body = f"{login.username_field}={{%username%}}&{login.password_field}={{%password%}}"
        context["authentication"] = {
            "method": "form",
            "parameters": {
                "loginPageUrl": login.login_url,
                "loginRequestUrl": login.login_request_url or login.login_url,
                "loginRequestBody": body,
            },
            "verification": verification,
        }

    jobs = [
        {"type": "spider", "parameters": {"context": "target", "user": "user", "url": base_url}},
        {
            "type": "spiderAjax",
            "parameters": {"context": "target", "user": "user", "url": base_url, "maxDuration": 5},
        },
        {"type": "passiveScan-wait", "parameters": {}},
    ]
    if profile == "active":
        jobs.append(
            {
                "type": "activeScan",
                "parameters": {
                    "context": "target",
                    "user": "user",
                    "maxRuleDurationInMins": 5,
                    "delayInMs": max(0, 1000 // max(rps, 1)),
                },
            }
        )
    jobs.append(
        {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": "/zap/wrk",
                "reportFile": report_name,
            },
        }
    )

    plan = {
        "env": {
            "contexts": [context],
            "parameters": {"failOnError": False, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": jobs,
    }
    return yaml.safe_dump(plan, allow_unicode=True, sort_keys=False), [login.password_env]


def _escape(url: str) -> str:
    return re.escape(url)
