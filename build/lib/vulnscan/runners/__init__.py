from .base import RunContext, Runner, RunResult
from .nmap import NmapRunner
from .nuclei import NucleiRunner
from .zap import ZapRunner

RUNNERS: dict[str, type[Runner]] = {
    "nmap": NmapRunner,
    "nuclei": NucleiRunner,
    "zap": ZapRunner,
}

__all__ = ["RUNNERS", "RunContext", "RunResult", "Runner"]
