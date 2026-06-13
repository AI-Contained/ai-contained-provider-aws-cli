"""Subprocess wrapper with stdout relay, buffering, and upstream chaining."""

import asyncio
from dataclasses import dataclass, field
from typing import TypedDict


class PiperResponse(TypedDict):
    """Raw output and exit code from a PiperProcess run."""

    exit_code: int
    stdout: str
    stderr: str
    is_truncated: bool


@dataclass
class _Config:
    args: list[str]
    env: dict[str, str]
    max_buffer: int
    upstream: "PiperProcess | None" = None


@dataclass
class _Output:
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    is_truncated: bool = False
    exit_code: int = 0


@dataclass
class _Command:
    process: asyncio.subprocess.Process
    pipe: asyncio.StreamReader
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
    process's stdin. Use as an async context manager; call wait() inside to
    collect results, or exit without wait() to kill the process.
    """

    def __init__(
        self,
        args: list[str],
        env: dict[str, str],
        upstream: "PiperProcess | None" = None,
        max_buffer: int = 200_000,
    ) -> None:
        """Initialize with subprocess args and configuration."""
        self._config = _Config(args=args, env=env, max_buffer=max_buffer, upstream=upstream)
        self._output = _Output()
        self._command: _Command | None = None

    async def __aenter__(self) -> "PiperProcess":
        """Start the subprocess."""
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Stop the subprocess if still running."""
        assert self._command is not None
        if self._command.process.returncode is None:
            await self.stop()

    async def start(self) -> None:
        """Spawn the subprocess and begin relaying stdout."""
        process = await asyncio.create_subprocess_exec(
            *self._config.args,
            env=self._config.env,
            stdin=asyncio.subprocess.PIPE if self._config.upstream is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._command = _Command(
            process=process,
            pipe=asyncio.StreamReader(),
            relay_stdout=asyncio.create_task(self._relay_stdout(process)),
            read_stderr=asyncio.create_task(self._read_stderr(process)),
            relay_stdin=asyncio.create_task(self._relay_stdin(process)) if self._config.upstream is not None else None,
        )

    @property
    def stdout(self) -> asyncio.StreamReader:
        """Relay pipe — readable by the next PiperProcess via upstream=."""
        assert self._command is not None, "call start() before accessing stdout"
        return self._command.pipe

    async def wait(self) -> PiperResponse:
        """Await process completion and return a PiperResponse."""
        assert self._command is not None, "call start() before wait()"
        await self._command.drain()
        self._output.exit_code = await self._command.process.wait()
        return PiperResponse(
            exit_code=self._output.exit_code,
            stdout=self._output.stdout.decode(errors="replace"),
            stderr=self._output.stderr.decode(errors="replace"),
            is_truncated=self._output.is_truncated,
        )

    async def stop(self) -> None:
        """Kill this process, propagate upstream, and block until all are dead."""
        assert self._command is not None, "call start() before stop()"
        self._command.process.kill()
        if self._config.upstream is not None:
            await self._config.upstream.stop()
        await self._command.drain()
        self._output.exit_code = await self._command.process.wait()

    async def _relay_stdout(self, process: asyncio.subprocess.Process) -> None:
        assert self._command is not None
        assert process.stdout is not None
        # phase 1: fill buffer and feed pipe simultaneously
        while len(self._output.stdout) < self._config.max_buffer:
            chunk = await process.stdout.read(4096)
            if not chunk:
                self._command.pipe.feed_eof()
                return
            space = self._config.max_buffer - len(self._output.stdout)
            self._output.stdout.extend(chunk[:space])
            self._command.pipe.feed_data(chunk)
            if len(chunk) > space:
                self._output.is_truncated = True
                break
        # phase 2: buffer full — feed pipe only
        while chunk := await process.stdout.read(4096):
            self._output.is_truncated = True
            self._command.pipe.feed_data(chunk)
        self._command.pipe.feed_eof()

    async def _read_stderr(self, process: asyncio.subprocess.Process) -> None:
        assert process.stderr is not None
        self._output.stderr.extend(await process.stderr.read())

    async def _relay_stdin(self, process: asyncio.subprocess.Process) -> None:
        assert self._config.upstream is not None
        assert process.stdin is not None
        while chunk := await self._config.upstream.stdout.read(4096):
            process.stdin.write(chunk)
            await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
