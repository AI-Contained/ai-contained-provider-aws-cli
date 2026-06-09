"""Subprocess wrapper with stdout relay, buffering, and upstream chaining."""

import asyncio
from dataclasses import dataclass


@dataclass
class PiperResult:
    exit_code: int
    stdout: str
    stderr: str
    is_truncated: bool


@dataclass
class _Started:
    process: asyncio.subprocess.Process
    relay_stdout: asyncio.Task[None]
    read_stderr: asyncio.Task[None]
    relay_stdin: asyncio.Task[None] | None

    async def drain(self) -> None:
        tasks = [self.relay_stdout, self.read_stderr]
        if self.relay_stdin is not None:
            tasks.append(self.relay_stdin)
        await asyncio.gather(*tasks)


class PiperProcess:
    """Runs a subprocess, buffers stdout up to max_buffer, and relays it downstream.

    Chain processes via upstream=: the upstream's stdout pipe becomes this
    process's stdin. Call wait() on the terminal process to collect results.
    """

    def __init__(
        self,
        args: list[str],
        env: dict[str, str],
        upstream: "PiperProcess | None" = None,
        max_buffer: int = 200_000,
    ) -> None:
        self._args = args
        self._env = env
        self._upstream = upstream
        self._max_buffer = max_buffer
        self._stdout_buffer = bytearray()
        self._is_truncated = False
        self._stdout_pipe = asyncio.StreamReader()
        self._result = PiperResult(exit_code=0, stdout="", stderr="", is_truncated=False)
        self._started: _Started | None = None

    async def start(self) -> None:
        """Spawn the subprocess and begin relaying stdout."""
        process = await asyncio.create_subprocess_exec(
            *self._args,
            env=self._env,
            stdin=asyncio.subprocess.PIPE if self._upstream is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._started = _Started(
            process=process,
            relay_stdout=asyncio.create_task(self._relay_stdout(process)),
            read_stderr=asyncio.create_task(self._read_stderr(process)),
            relay_stdin=asyncio.create_task(self._relay_stdin(process)) if self._upstream is not None else None,
        )

    @property
    def stdout(self) -> asyncio.StreamReader:
        """Relay pipe — readable by the next PiperProcess via upstream=."""
        return self._stdout_pipe

    @property
    def result(self) -> PiperResult:
        """Current state of the owned result — may be incomplete until wait()."""
        return self._result

    async def wait(self) -> PiperResult:
        """Await process completion and return the final PiperResult."""
        assert self._started is not None, "call start() before wait()"
        await self._started.drain()
        self._result.exit_code = await self._started.process.wait()
        self._result.stdout = self._stdout_buffer.decode(errors="replace")
        self._result.is_truncated = self._is_truncated
        return self._result

    async def stop(self) -> None:
        """Kill this process, propagate upstream, and block until all are dead."""
        assert self._started is not None, "call start() before stop()"
        self._started.process.kill()
        if self._upstream is not None:
            await self._upstream.stop()
        await self._started.drain()
        self._result.exit_code = await self._started.process.wait()
        self._result.stdout = self._stdout_buffer.decode(errors="replace")
        self._result.is_truncated = self._is_truncated

    async def _relay_stdout(self, process: asyncio.subprocess.Process) -> None:
        # phase 1: fill buffer and feed pipe simultaneously
        while len(self._stdout_buffer) < self._max_buffer:
            chunk = await process.stdout.read(4096)  # type: ignore[union-attr]
            if not chunk:
                self._stdout_pipe.feed_eof()
                return
            space = self._max_buffer - len(self._stdout_buffer)
            self._stdout_buffer.extend(chunk[:space])
            self._stdout_pipe.feed_data(chunk)
            if len(chunk) > space:
                self._is_truncated = True
                break
        # phase 2: buffer full — feed pipe only
        while chunk := await process.stdout.read(4096):  # type: ignore[union-attr]
            self._is_truncated = True
            self._stdout_pipe.feed_data(chunk)
        self._stdout_pipe.feed_eof()

    async def _read_stderr(self, process: asyncio.subprocess.Process) -> None:
        self._result.stderr = (await process.stderr.read()).decode(errors="replace")  # type: ignore[union-attr]

    async def _relay_stdin(self, process: asyncio.subprocess.Process) -> None:
        assert self._upstream is not None
        assert process.stdin is not None
        while chunk := await self._upstream.stdout.read(4096):
            process.stdin.write(chunk)
            await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
