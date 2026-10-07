"""画面から開始した診断をバックグラウンドで 1 件ずつ実行する。"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Job:
    id: str
    target: str
    profile: str
    tools: list[str]
    actor: str | None
    status: str = "queued"
    log: list[str] = field(default_factory=list)
    run_ids: list[int] = field(default_factory=list)
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.status in ("queued", "running")


class Busy(RuntimeError):
    pass


class JobManager:
    """同時に動く診断は 1 件まで（対象への負荷と取り違えを防ぐため）。"""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def current(self) -> Job | None:
        return next((j for j in self._jobs.values() if j.active), None)

    def recent(self, limit: int = 10) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]

    def submit(
        self,
        target: str,
        profile: str,
        tools: list[str],
        actor: str | None,
        work: Callable[[Job], None],
        background: bool = True,
    ) -> Job:
        with self._lock:
            if self.current():
                raise Busy("ほかの診断が実行中です")
            job = Job(uuid.uuid4().hex[:12], target, profile, tools, actor)
            self._jobs[job.id] = job

        def runner() -> None:
            job.status = "running"
            try:
                work(job)
                job.status = "done"
            except Exception as e:  # 画面に理由を出すため握りつぶさず記録する
                job.status = "failed"
                job.error = str(e)
                job.log.append(f"エラー: {e}")
            finally:
                job.finished_at = datetime.now(UTC)

        if background:
            threading.Thread(target=runner, name=f"scan-{job.id}", daemon=True).start()
        else:
            runner()
        return job
