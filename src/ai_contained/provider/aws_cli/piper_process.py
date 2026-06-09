"""Subprocess wrapper with stdout relay, buffering, and upstream chaining."""

import asyncio
from dataclasses import dataclass, field


@dataclass
class PiperResult:
    exit_code: int
    stdout: str
    stderr: str
    is_truncated: bool


class PiperProcess:
    """Runs a subprocess and tees its stdout into a buffer and a relay pipe.

    Chain processes via upstream=: the upstream's relay pipe becomes this
    process's stdin. Call stdout on source processes, wait() on the terminal.
    """

    def __init__(
        self,
        args: list[str],
        env: dict[str, str],
        upstream: "PiperProcess | None" = None,
        max_buffer: int = 200_000,
    ) -> None:
        raise NotImplementedError

    async def start(self) -> None:
        """Spawn the subprocess and begin relaying stdout into result."""
        raise NotImplementedError

    @property
    def stdout(self) -> asyncio.StreamReader:
        """Relay pipe — pass as upstream= to the next PiperProcess."""
        raise NotImplementedError

    @property
    def result(self) -> PiperResult:
        """Current state of the owned result — may be incomplete until wait()."""
        raise NotImplementedError

    async def wait(self) -> PiperResult:
        """Await process completion and return the final PiperResult."""
        raise NotImplementedError

    async def stop(self) -> None:
        """Kill this process, propagate upstream, and block until all are dead."""
        raise NotImplementedError
