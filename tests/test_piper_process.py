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
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_captures_stderr(env) -> None:
            expected = PiperResult(exit_code=0, stdout="", stderr="something went wrong", is_truncated=False)
            async with PiperProcess(py("import sys", f"sys.stderr.write('{expected.stderr}')"), env=env) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_captures_stdout_and_stderr(env) -> None:
            expected = PiperResult(exit_code=0, stdout="out", stderr="err", is_truncated=False)
            async with PiperProcess(
                py("import sys", f"print('{expected.stdout}', end='')", f"sys.stderr.write('{expected.stderr}')"),
                env=env,
            ) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_reflects_non_zero_exit_code(env) -> None:
            expected = PiperResult(exit_code=42, stdout="", stderr="", is_truncated=False)
            async with PiperProcess(py("import sys", f"sys.exit({expected.exit_code})"), env=env) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_handles_empty_output(env) -> None:
            expected = PiperResult(exit_code=0, stdout="", stderr="", is_truncated=False)
            async with PiperProcess(py("pass"), env=env) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_is_not_truncated_when_output_is_within_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * (max_buffer - 1), stderr="", is_truncated=False)
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env, max_buffer=max_buffer) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_is_not_truncated_when_output_is_exactly_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=False)
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env, max_buffer=max_buffer) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

        async def it_truncates_stdout_when_output_exceeds_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=True)
            async with PiperProcess(py(f"print('x' * {max_buffer + 1}, end='')"), env=env, max_buffer=max_buffer) as proc:
                result = await proc.wait()
            assert_that(result).is_equal_to(expected)

    def describe_result():
        async def it_is_a_piper_result_before_completion(env) -> None:
            async with PiperProcess(py("print('hello', end='')"), env=env) as proc:
                assert_that(proc.result).is_instance_of(PiperResult)

        async def it_matches_wait_after_completion(env) -> None:
            async with PiperProcess(py("print('hello', end='')"), env=env) as proc:
                result = await proc.wait()
            assert_that(proc.result).is_equal_to(result)

    def describe_stdout():
        async def it_returns_a_stream_reader(env) -> None:
            async with PiperProcess(py("print('hello', end='')"), env=env) as proc:
                assert_that(proc.stdout).is_instance_of(asyncio.StreamReader)

        async def it_relays_output_to_downstream_stdin(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env) as upstream:
                async with PiperProcess(["cat"], env=env, upstream=upstream) as downstream:
                    result = await downstream.wait()
            assert_that(result).is_equal_to(expected)

        async def it_fills_buffer_independently_of_downstream(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env) as upstream:
                async with PiperProcess(["cat"], env=env, upstream=upstream) as downstream:
                    await downstream.wait()
                result = await upstream.wait()
            assert_that(result).is_equal_to(expected)

        async def it_fills_buffer_even_when_downstream_fails(env) -> None:
            expected = PiperResult(exit_code=0, stdout="hello", stderr="", is_truncated=False)
            async with PiperProcess(py(f"print('{expected.stdout}', end='')"), env=env) as upstream:
                async with PiperProcess(py("import sys", "sys.exit(1)"), env=env, upstream=upstream) as downstream:
                    downstream_result = await downstream.wait()
                upstream_result = await upstream.wait()
            assert_that(downstream_result.exit_code).is_not_equal_to(0)
            assert_that(upstream_result).is_equal_to(expected)

        async def it_caps_buffer_at_max_buffer(env) -> None:
            max_buffer = 100
            expected = PiperResult(exit_code=0, stdout="x" * max_buffer, stderr="", is_truncated=True)
            async with PiperProcess(py(f"print('x' * {max_buffer + 1}, end='')"), env=env, max_buffer=max_buffer) as upstream:
                async with PiperProcess(["cat"], env=env, upstream=upstream) as downstream:
                    await downstream.wait()
                result = await upstream.wait()
            assert_that(result).is_equal_to(expected)

    def describe_stop():
        async def it_terminates_the_process(env) -> None:
            async with PiperProcess(["sleep", "999"], env=env) as proc:
                pass
            assert_that(proc.result.exit_code).is_not_equal_to(0)

        async def it_propagates_stop_to_upstream(env) -> None:
            async with PiperProcess(["sleep", "999"], env=env) as upstream:
                async with PiperProcess(["cat"], env=env, upstream=upstream) as downstream:
                    pass
            assert_that(upstream.result.exit_code).is_not_equal_to(0)

        async def it_is_safe_with_no_upstream(env) -> None:
            async with PiperProcess(["sleep", "999"], env=env) as proc:
                pass
            assert_that(proc.result.exit_code).is_not_equal_to(0)
