"""スキャナ実行の共通処理。各ツールはコマンド組み立てと出力パースだけを実装する。"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding
from ..scope import Decision, LoginConfig, Target


@dataclass
class RunContext:
    decision: Decision
    workdir: Path
    use_docker: bool = False
    timeout: int = 3600

    @property
    def target(self) -> Target:
        return Target.parse(self.decision.target)

    @property
    def profile(self) -> str:
        return self.decision.profile

    @property
    def login(self) -> LoginConfig | None:
        auth = self.decision.authorization
        return auth.login if auth else None


@dataclass
class RunResult:
    tool: str
    command: list[str]
    findings: list[Finding] = field(default_factory=list)
    skipped: str | None = None
    error: str | None = None
    returncode: int | None = None


class Runner:
    name: str = ""
    binary: str = ""
    # イメージはバージョンを固定する（:latest だと診断内容が予告なく変わり、差分が揺れる）。
    # 更新するときは環境変数 VULNSCAN_IMAGE_<NAME>（例: VULNSCAN_IMAGE_NUCLEI）で上書きできる
    image: str = ""
    ok_returncodes: tuple[int, ...] = (0,)

    def build_command(self, ctx: RunContext) -> list[str] | None:
        """実行コマンドを返す。この対象では実行しない場合は None。"""
        raise NotImplementedError

    def parse(self, stdout: str, ctx: RunContext) -> list[Finding]:
        raise NotImplementedError

    def skip_reason(self, ctx: RunContext) -> str:
        return "この対象には適用できません"

    @property
    def image_ref(self) -> str:
        return os.environ.get(f"VULNSCAN_IMAGE_{self.name.upper()}") or self.image

    def docker_prefix(self, ctx: RunContext) -> list[str]:
        return ["docker", "run", "--rm", "--network", "host", self.image_ref]

    def wrap(self, args: list[str], ctx: RunContext) -> list[str]:
        if ctx.use_docker:
            return self.docker_prefix(ctx) + args
        return [self.binary, *args]

    def available(self, ctx: RunContext) -> bool:
        return shutil.which("docker" if ctx.use_docker else self.binary) is not None

    def run(self, ctx: RunContext, dry_run: bool = False) -> RunResult:
        cmd = self.build_command(ctx)
        if cmd is None:
            return RunResult(self.name, [], skipped=self.skip_reason(ctx))
        result = RunResult(self.name, cmd)
        if dry_run:
            result.skipped = "dry-run"
            return result
        if not self.available(ctx):
            result.error = f"{cmd[0]} が見つかりません（--docker の利用も検討してください）"
            return result
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=ctx.timeout, cwd=ctx.workdir
            )
        except subprocess.TimeoutExpired:
            result.error = f"{ctx.timeout} 秒でタイムアウトしました"
            return result
        result.returncode = proc.returncode
        if proc.returncode not in self.ok_returncodes:
            result.error = f"終了コード {proc.returncode}: {proc.stderr.strip()[-2000:]}"
            return result
        try:
            result.findings = self.parse(proc.stdout, ctx)
        except Exception as e:  # パース失敗は他ツールの実行を止めない
            result.error = f"出力の解析に失敗しました: {e}"
        return result
