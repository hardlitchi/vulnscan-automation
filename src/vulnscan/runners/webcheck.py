"""webcheck: 外部ツールに頼らない内蔵の Web アプリ診断（OWASP Top 10 相当の軽量チェック）。

安全側の既定方針:
- 読み取り中心。書き込み・破壊的ペイロードは一切送らない（どのプロファイルでも）。
- 叩く URL は必ず同じ承認の範囲内（ctx.in_scope）に限る。
- 承認のレート制限（rps）に従ってリクエスト間隔をあける。
- 失敗しても例外を投げず、他ツールの実行を止めない（engine が RunResult.error を記録）。

プロファイル別の深さ:
- passive  : 対象 URL を 1 回だけ GET し、応答（ヘッダ・Cookie・本文）から判定する受動チェックのみ。
- standard : 受動チェックに加え、同一スコープ内の安全な GET 探索（既知の機微ファイル・
             入力の反射・DB エラーの反射）を少数だけ行う。
- active   : standard をやや広く行う。破壊的検査は含まない。
"""

from __future__ import annotations

import http.client
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..models import Finding
from .base import RunContext, Runner, RunResult

USER_AGENT = "vulnscan-webcheck/1.0 (authorized security assessment)"
_OWASP = "https://owasp.org/www-project-top-ten/"

# standard / active で GET する既知の機微ファイル。200 かつ署名に一致したときのみ報告する。
# （非破壊の読み取り。パスは対象 URL 基準で解決し、スコープ内のものだけ叩く。）
SENSITIVE_PATHS: dict[str, tuple[str, re.Pattern[str]]] = {
    "/.git/config": ("Git リポジトリ設定", re.compile(r"\[core\]", re.I)),
    "/.env": ("環境変数ファイル", re.compile(r"^\s*[A-Z0-9_]+\s*=", re.M)),
    "/.svn/entries": ("Subversion メタデータ", re.compile(r"^\d+\s*$|svn", re.I)),
    "/.DS_Store": ("macOS ディレクトリ情報", re.compile(r"Bud1", re.I)),
    "/server-status": ("Apache server-status", re.compile(r"Apache Server Status", re.I)),
    "/phpinfo.php": ("phpinfo 出力", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    "/.aws/credentials": ("AWS 認証情報", re.compile(r"aws_access_key_id", re.I)),
    "/wp-config.php.bak": (
        "WordPress 設定のバックアップ",
        re.compile(r"DB_PASSWORD|DB_NAME", re.I),
    ),
}
# active でのみ追加する探索パス
EXTRA_PATHS_ACTIVE: dict[str, tuple[str, re.Pattern[str]]] = {
    "/backup.zip": ("バックアップアーカイブ", re.compile(r".", re.S)),
    "/.git/HEAD": ("Git HEAD", re.compile(r"ref:\s*refs/", re.I)),
}

# DB エラーが本文に反射したことを示す署名（SQL インジェクションの兆候。値は変更しない読み取り探索）。
SQL_ERROR_SIGNATURES = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE\[|PG::SyntaxError|"
    r"SQLiteException|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"Microsoft OLE DB Provider for SQL Server|psql:|valid MySQL result|"
    r"com\.mysql\.jdbc|org\.postgresql\.util\.PSQLException",
    re.I,
)
_TOKENISH = re.compile(r"csrf|token|nonce|authenticity|verification|xsrf", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_METHOD_RE = re.compile(r'method\s*=\s*["\']?\s*post', re.I)
_HIDDEN_NAME_RE = re.compile(r'<input\b[^>]*type\s*=\s*["\']?hidden[^>]*>', re.I)
_NAME_ATTR_RE = re.compile(r'name\s*=\s*["\']?([^"\'\s>]+)', re.I)
_HTTP_RESOURCE_RE = re.compile(r'(?:src|href|action)\s*=\s*["\'](http://[^"\']+)["\']', re.I)


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: str
    error: str | None = None

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def is_html(self) -> bool:
        ct = (self.header("content-type") or "").lower()
        return "html" in ct or (not ct and "<html" in self.body[:2000].lower())


Fetcher = Callable[[str, int], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクトは追わない。スコープ外へ出ないため、また応答ヘッダをそのまま見るため。"""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


def default_fetch(url: str, timeout: int) -> HttpResponse:
    """標準ライブラリだけで GET する。リダイレクトは追わない。失敗は error に入れて返す。"""
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
        return _to_response(url, resp)
    except urllib.error.HTTPError as e:  # 4xx/5xx も応答として扱う
        return _to_response(url, e)
    except (urllib.error.URLError, http.client.HTTPException, ssl.SSLError, OSError) as e:
        return HttpResponse(url, 0, [], "", error=str(e))


def _to_response(url: str, resp) -> HttpResponse:  # noqa: ANN001
    headers = list(resp.headers.items())
    raw = resp.read(512 * 1024)  # 本文は 512KB まで（巨大応答で詰まらないように）
    charset = resp.headers.get_content_charset() or "utf-8"
    body = raw.decode(charset, errors="replace")
    status = getattr(resp, "status", None) or getattr(resp, "code", 0) or 0
    return HttpResponse(url, int(status), headers, body)


class WebCheckRunner(Runner):
    name = "webcheck"
    binary = ""  # 外部バイナリ不要（内蔵）

    def __init__(self, fetch: Fetcher | None = None) -> None:
        self._fetch = fetch or default_fetch

    def skip_reason(self, ctx: RunContext) -> str:
        return "webcheck は URL を指定した対象のみ実行します"

    def available(self, ctx: RunContext) -> bool:
        return True  # 内蔵なので常に利用可能

    def build_command(self, ctx: RunContext) -> list[str] | None:
        url = ctx.target.url
        if not url:
            return None
        rps = ctx.decision.rate_limit.rps
        # 実行可能なコマンドではなく、監査ログ・表示用の説明。
        return ["(内蔵) webcheck", url, f"profile={ctx.profile}", f"rps={rps}"]

    def run(self, ctx: RunContext, dry_run: bool = False) -> RunResult:
        cmd = self.build_command(ctx)
        if cmd is None:
            return RunResult(self.name, [], skipped=self.skip_reason(ctx))
        if dry_run:
            return RunResult(self.name, cmd, skipped="dry-run")
        result = RunResult(self.name, cmd, returncode=0)
        try:
            result.findings = self._scan(ctx)
        except Exception as e:  # 内蔵チェックの不具合で他ツールを止めない
            result.error = f"webcheck の実行に失敗しました: {e}"
        return result

    # ------------------------------------------------------------------ 本体

    def _scan(self, ctx: RunContext) -> list[Finding]:
        url = ctx.target.url
        assert url is not None
        rps = max(1, ctx.decision.rate_limit.rps)
        budget = _RequestBudget(rps, timeout=min(ctx.timeout, 30))
        target = ctx.decision.target

        root = budget.get(self._fetch, url)
        if root.error:
            raise RuntimeError(f"{url} に接続できません: {root.error}")

        findings: list[Finding] = []
        findings += _check_transport(root, target)
        findings += _check_security_headers(root, target)
        findings += _check_cookies(root, target)
        findings += _check_info_disclosure(root, target)
        if root.is_html:
            findings += _check_directory_listing(root, target)
            findings += _check_mixed_content(root, target)
            findings += _check_csrf_forms(root, target)

        if ctx.profile in ("standard", "active"):
            findings += self._active_probes(ctx, budget, root)

        return findings

    def _active_probes(
        self, ctx: RunContext, budget: _RequestBudget, root: HttpResponse
    ) -> list[Finding]:
        url = ctx.target.url
        assert url is not None
        target = ctx.decision.target
        findings: list[Finding] = []

        # 1) 既知の機微ファイルの露出（スコープ内かつ署名一致のみ報告）
        paths = dict(SENSITIVE_PATHS)
        if ctx.profile == "active":
            paths.update(EXTRA_PATHS_ACTIVE)
        for path, (label, sig) in paths.items():
            candidate = urljoin(url, path)
            if not ctx.in_scope(candidate):
                continue
            resp = budget.get(self._fetch, candidate)
            if resp.error or resp.status != 200 or not sig.search(resp.body):
                continue
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id="sensitive-file-exposed",
                    title=f"機微なファイルが公開されています（{label}）",
                    severity="high",
                    target=target,
                    location=candidate,
                    evidence=f"HTTP 200 / {label}",
                    description=(
                        f"{path} に誰でもアクセスでき、{label}が外部から読み取れる状態です。"
                        "認証情報やソースコードの流出につながります。"
                    ),
                    remediation="当該ファイルを公開ディレクトリから削除し、Web サーバで拒否してください。",
                    references=[
                        _OWASP,
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                )
            )

        # 2) 入力の反射（安全なカナリア）と DB エラーの反射（値を変更しない読み取り探索）
        params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        if params:
            limit = 5 if ctx.profile == "active" else 3
            findings += self._probe_parameters(ctx, budget, url, params[:limit], target)
        return findings

    def _probe_parameters(
        self,
        ctx: RunContext,
        budget: _RequestBudget,
        url: str,
        params: list[tuple[str, str]],
        target: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, (name, _value) in enumerate(params):
            canary = f"vulnscanREF{i}Z9"
            refl_url = _replace_param(url, i, canary)
            if ctx.in_scope(refl_url):
                resp = budget.get(self._fetch, refl_url)
                if not resp.error and resp.is_html and canary in resp.body:
                    findings.append(
                        Finding(
                            tool=self.name,
                            rule_id=f"reflected-parameter:{name}",
                            title=f"入力がそのまま応答に反映されています（パラメータ {name}）",
                            severity="low",
                            target=target,
                            location=refl_url,
                            evidence=f"カナリア {canary} が本文にそのまま出力されました",
                            description=(
                                f"パラメータ {name} の値が HTML にそのまま反映されました。"
                                "エスケープ処理によっては反射型 XSS の起点になり得ます（要人手確認）。"
                            ),
                            remediation="出力時に文脈に応じた HTML エスケープを行ってください。",
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    )

            # 末尾にシングルクオートを 1 つ足すだけの非破壊プローブ。DB エラーが出れば SQLi の兆候。
            sqli_url = _replace_param(url, i, _value + "'")
            if ctx.in_scope(sqli_url):
                resp = budget.get(self._fetch, sqli_url)
                if not resp.error and SQL_ERROR_SIGNATURES.search(resp.body):
                    m = SQL_ERROR_SIGNATURES.search(resp.body)
                    findings.append(
                        Finding(
                            tool=self.name,
                            rule_id=f"sql-error-reflected:{name}",
                            title=f"SQL エラーが応答に表れました（パラメータ {name}）",
                            severity="high",
                            target=target,
                            location=sqli_url,
                            evidence=(m.group(0) if m else "")[:200],
                            description=(
                                f"パラメータ {name} にシングルクオートを 1 つ加えたところ、"
                                "データベースのエラーがそのまま返りました。SQL インジェクションの可能性が高いです。"
                            ),
                            remediation="プレースホルダ（プリペアドステートメント）を使い、入力値を直接 SQL に連結しないでください。",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    )
        return findings


# ---------------------------------------------------------------- 受動チェック


def _check_transport(resp: HttpResponse, target: str) -> list[Finding]:
    scheme = urlsplit(resp.url).scheme
    if scheme == "http":
        return [
            Finding(
                tool="webcheck",
                rule_id="cleartext-transport",
                title="通信が暗号化されていません（HTTP）",
                severity="medium",
                target=target,
                location=resp.url,
                description="平文の HTTP で配信されており、通信内容の盗聴・改ざんの恐れがあります。",
                remediation="HTTPS を有効にし、HTTP から HTTPS へリダイレクトしてください。",
                references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
            )
        ]
    return []


def _check_security_headers(resp: HttpResponse, target: str) -> list[Finding]:
    https = urlsplit(resp.url).scheme == "https"
    csp = resp.header("content-security-policy") or ""
    checks: list[tuple[str, bool, str, str, str]] = [
        (
            "hsts-missing",
            https and not resp.header("strict-transport-security"),
            "medium",
            "HSTS ヘッダがありません",
            "Strict-Transport-Security ヘッダを付与し、HTTPS の利用を強制してください。",
        ),
        (
            "csp-missing",
            not csp,
            "medium",
            "Content-Security-Policy がありません",
            "Content-Security-Policy を設定し、スクリプトの読み込み元を制限してください。",
        ),
        (
            "x-content-type-options-missing",
            (resp.header("x-content-type-options") or "").lower() != "nosniff",
            "low",
            "X-Content-Type-Options: nosniff がありません",
            "X-Content-Type-Options: nosniff を付与し、MIME スニッフィングを防いでください。",
        ),
        (
            "clickjacking-protection-missing",
            not resp.header("x-frame-options") and "frame-ancestors" not in csp.lower(),
            "medium",
            "クリックジャッキング対策がありません",
            "X-Frame-Options か CSP の frame-ancestors で埋め込みを制限してください。",
        ),
        (
            "referrer-policy-missing",
            not resp.header("referrer-policy"),
            "low",
            "Referrer-Policy がありません",
            "Referrer-Policy を設定し、リファラの漏えいを抑えてください。",
        ),
    ]
    out: list[Finding] = []
    for rule_id, missing, sev, title, remediation in checks:
        if missing:
            out.append(
                Finding(
                    tool="webcheck",
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    target=target,
                    location=resp.url,
                    remediation=remediation,
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                )
            )
    return out


def _check_cookies(resp: HttpResponse, target: str) -> list[Finding]:
    https = urlsplit(resp.url).scheme == "https"
    out: list[Finding] = []
    for raw in resp.header_all("set-cookie"):
        attrs = raw.lower()
        cname = raw.split("=", 1)[0].strip()
        problems = []
        if https and "secure" not in attrs:
            problems.append(("secure", "Secure 属性がない"))
        if "httponly" not in attrs:
            problems.append(("httponly", "HttpOnly 属性がない"))
        if "samesite" not in attrs:
            problems.append(("samesite", "SameSite 属性がない"))
        for flag, desc in problems:
            out.append(
                Finding(
                    tool="webcheck",
                    rule_id=f"cookie-{flag}-missing:{cname}",
                    title=f"Cookie の属性不足（{cname}: {desc}）",
                    severity="low",
                    target=target,
                    location=resp.url,
                    evidence=f"Set-Cookie: {cname}",
                    description=f"Cookie {cname} に {desc} ため、盗聴やクロスサイトでの送信の恐れがあります。",
                    remediation="セッション系 Cookie には Secure・HttpOnly・SameSite 属性を付けてください。",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                )
            )
    return out


def _check_info_disclosure(resp: HttpResponse, target: str) -> list[Finding]:
    out: list[Finding] = []
    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        val = resp.header(hdr)
        if val and re.search(r"\d", val):
            out.append(
                Finding(
                    tool="webcheck",
                    rule_id=f"version-disclosure:{hdr}",
                    title=f"ソフトウェアのバージョンが露出しています（{hdr}）",
                    severity="info",
                    target=target,
                    location=resp.url,
                    evidence=f"{hdr}: {val}",
                    description="応答ヘッダに製品名やバージョンが含まれ、攻撃対象の絞り込みに使われ得ます。",
                    remediation="不要なバージョン情報を応答ヘッダから取り除いてください。",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                )
            )
    return out


def _check_directory_listing(resp: HttpResponse, target: str) -> list[Finding]:
    if re.search(r"<title>\s*Index of /|Directory listing for ", resp.body, re.I):
        return [
            Finding(
                tool="webcheck",
                rule_id="directory-listing",
                title="ディレクトリの一覧が表示されています",
                severity="medium",
                target=target,
                location=resp.url,
                description="ディレクトリ一覧が有効で、意図しないファイルが見える恐れがあります。",
                remediation="Web サーバのディレクトリ一覧（autoindex）を無効にしてください。",
                references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
            )
        ]
    return []


def _check_mixed_content(resp: HttpResponse, target: str) -> list[Finding]:
    if urlsplit(resp.url).scheme != "https":
        return []
    hits = _HTTP_RESOURCE_RE.findall(resp.body)
    if not hits:
        return []
    return [
        Finding(
            tool="webcheck",
            rule_id="mixed-content",
            title="HTTPS ページが HTTP のリソースを読み込んでいます",
            severity="low",
            target=target,
            location=resp.url,
            evidence=", ".join(sorted(set(hits))[:5])[:2000],
            description="HTTPS ページ内に平文 HTTP のリソース参照があり、改ざん・盗聴の恐れがあります。",
            remediation="すべてのリソースを HTTPS で参照してください。",
            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
        )
    ]


def _check_csrf_forms(resp: HttpResponse, target: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _FORM_RE.finditer(resp.body):
        block = m.group(0)
        if not _METHOD_RE.search(block):
            continue  # GET フォームは対象外
        hidden_names = []
        for hm in _HIDDEN_NAME_RE.finditer(block):
            nm = _NAME_ATTR_RE.search(hm.group(0))
            if nm:
                hidden_names.append(nm.group(1))
        if any(_TOKENISH.search(n) for n in hidden_names):
            continue  # トークンらしき hidden 入力がある
        out.append(
            Finding(
                tool="webcheck",
                rule_id="form-without-csrf-token",
                title="POST フォームに CSRF トークンが見当たりません",
                severity="low",
                target=target,
                location=resp.url,
                description=(
                    "送信系の POST フォームにトークンらしき hidden 項目がありません。"
                    "CSRF 対策が別の仕組みで行われているか、人手で確認してください。"
                ),
                remediation="フォームに CSRF トークンを埋め込むか、SameSite Cookie 等で保護してください。",
                references=["https://owasp.org/www-community/attacks/csrf"],
            )
        )
        break  # 1 ページにつき 1 件に抑える（過検知を避ける）
    return out


# ------------------------------------------------------------------ 補助


@dataclass
class _RequestBudget:
    """レート制限（rps）に従って GET の間隔をあける。"""

    rps: int
    timeout: int
    _last: float = field(default=0.0)

    def get(self, fetch: Fetcher, url: str) -> HttpResponse:
        wait = (1.0 / self.rps) - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        resp = fetch(url, self.timeout)
        self._last = time.monotonic()
        return resp


def _replace_param(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs[index] = (pairs[index][0], value)
    return urlunsplit(parts._replace(query=urlencode(pairs)))
