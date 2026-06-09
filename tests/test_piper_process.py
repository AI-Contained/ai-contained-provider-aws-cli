import asyncio
import os

import pytest
from assertpy import assert_that

from ai_contained.provider.aws_cli.piper_process import PiperProcess, PiperResult


def py(*statements: str) -> list[str]:
    """Return a python3 -c invocation for the given statements."""
    return ["python3", "-c", "; ".join(statements)]


def describe_PiperResult():
    def it_has_sane_defaults() -> None:
        expected = PiperResult(exit_code=0, stdout="", stderr="", is_truncated=False)
        assert_that(expected.exit_code).is_equal_to(0)
        assert_that(expected.stdout).is_equal_to("")
        assert_that(expected.stderr).is_equal_to("")
        assert_that(expected.is_truncated).is_false()


def describe_PiperProcess():
    @pytest.fixture
    def env() -> dict[str, str]:
        return {"PATH": os.environ["PATH"]}

    def describe_wait():
        async def it_captures_stdout(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            proc = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_captures_stderr(env) -> None:
            expected = PiperResult(exit_code=0, stdout="", stderr="something went wrong", is_truncated=False)
            proc = PiperProcess(py("import sys", f"sys.stderr.write('{expected.stderr}')"), env=env)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_captures_stdout_and_stderr(env) -> None:
            expected = PiperResult(exit_code=0, stdout="out", stderr="err", is_truncated=False)
            proc = PiperProcess(
                py("import sys", f"print('{expected.stdout}', end='')", f"sys.stderr.write('{expected.stderr}')"),
                env=env,
            )
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_reflects_non_zero_exit_code(env) -> None:
            expected = PiperResult(exit_code=42, stdout="", stderr="", is_truncated=False)
            proc = PiperProcess(py("import sys", f"sys.exit({expected.exit_code})"), env=env)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_handles_empty_output(env) -> None:
            expected = PiperResult(exit_code=0, stdout="", stderr="", is_truncated=False)
            proc = PiperProcess(py("pass"), env=env)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_is_not_truncated_when_output_is_within_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * (max_buffer - 1), stderr="", is_truncated=False)
            proc = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env, max_buffer=max_buffer)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_is_not_truncated_when_output_is_exactly_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=False)
            proc = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env, max_buffer=max_buffer)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_truncates_stdout_when_output_exceeds_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=True)
            proc = PiperProcess(py(f"print('x' * {max_buffer + 1}, end='')"), env=env, max_buffer=max_buffer)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(result).is_equal_to(expected)

    def describe_result():
        async def it_is_a_piper_result_before_completion(env) -> None:
            proc = PiperProcess(py("print('hello', end='')"), env=env)
            assert_that(await proc.start()).is_none()
            assert_that(proc.result).is_instance_of(PiperResult)
            await proc.wait()

        async def it_matches_wait_after_completion(env) -> None:
            proc = PiperProcess(py("print('hello', end='')"), env=env)
            assert_that(await proc.start()).is_none()
            result = await proc.wait()
            assert_that(proc.result).is_equal_to(result)

    def describe_stdout():
        async def it_returns_a_stream_reader(env) -> None:
            proc = PiperProcess(py("print('hello', end='')"), env=env)
            assert_that(await proc.start()).is_none()
            assert_that(proc.stdout).is_instance_of(asyncio.StreamReader)
            await proc.wait()

        async def it_relays_output_to_downstream_stdin(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            upstream = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env)
            assert_that(await upstream.start()).is_none()
            downstream = PiperProcess(["cat"], env=env, upstream=upstream)
            assert_that(await downstream.start()).is_none()
            result = await downstream.wait()
            assert_that(result).is_equal_to(expected)

        async def it_fills_buffer_independently_of_downstream(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            upstream = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env)
            assert_that(await upstream.start()).is_none()
            downstream = PiperProcess(["cat"], env=env, upstream=upstream)
            assert_that(await downstream.start()).is_none()
            await downstream.wait()
            await asyncio.wait_for(upstream.wait(), timeout=2.0)
            assert_that(upstream.result).is_equal_to(expected)

        async def it_fills_buffer_even_when_downstream_fails(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            upstream = PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env)
            assert_that(await upstream.start()).is_none()
            downstream = PiperProcess(py("import sys", "sys.exit(1)"), env=env, upstream=upstream)
            assert_that(await downstream.start()).is_none()
            downstream_result = await downstream.wait()
            assert_that(downstream_result.exit_code).is_not_equal_to(0)
            await asyncio.wait_for(upstream.wait(), timeout=2.0)
            assert_that(upstream.result).is_equal_to(expected)

        async def it_caps_buffer_at_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=True)
            upstream = PiperProcess(py(f"print('x' * {max_buffer + 1}, end='')"), env=env, max_buffer=max_buffer)
            assert_that(await upstream.start()).is_none()
            downstream = PiperProcess(["cat"], env=env, upstream=upstream)
            assert_that(await downstream.start()).is_none()
            await downstream.wait()
            await asyncio.wait_for(upstream.wait(), timeout=2.0)
            assert_that(upstream.result).is_equal_to(expected)

    def describe_stop():
        async def it_terminates_the_process(env) -> None:
            proc = PiperProcess(["sleep", "999"], env=env)
            assert_that(await proc.start()).is_none()
            assert_that(await proc.stop()).is_none()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pytest.fail("process was not stopped")

        async def it_propagates_stop_to_upstream(env) -> None:
            upstream = PiperProcess(["sleep", "999"], env=env)
            assert_that(await upstream.start()).is_none()
            downstream = PiperProcess(["cat"], env=env, upstream=upstream)
            assert_that(await downstream.start()).is_none()
            assert_that(await downstream.stop()).is_none()
            try:
                await asyncio.wait_for(upstream.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pytest.fail("stop did not propagate to upstream")

        async def it_is_safe_with_no_upstream(env) -> None:
            proc = PiperProcess(["sleep", "999"], env=env)
            assert_that(await proc.start()).is_none()
            assert_that(await proc.stop()).is_none()
