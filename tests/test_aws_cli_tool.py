import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client

from ai_contained.core.mcp.testing import Elicitor
from ai_contained.provider.aws_cli import register
from ai_contained.provider.aws_cli.aws_cli_tool import AwsCliTool
from ai_contained.provider.aws_cli.command_filter import build_filters
from ai_contained.provider.aws_secrets.types import Role

def describe_register():
    async def it_exposes_read_and_write_tools() -> None:
        mcp = FastMCP("test")

        await register(mcp)

        tool_names = [t.name for t in await mcp.list_tools()]
        assert_that(tool_names).contains("aws_read", "aws_write")

    async def it_exposes_two_tools_only() -> None:
        mcp = FastMCP("test")

        await register(mcp)

        assert_that(await mcp.list_tools()).is_length(2)


def describe_AwsCliTool():
    _ACCOUNT = "123456789012"

    @dataclass
    class Mock:
        elicitor: Elicitor
        env: dict

    @pytest.fixture
    async def run_setup():
        tests_bin = str(Path(__file__).parent / "bin")
        mock = Mock(
            elicitor=Elicitor(),
            env={
                "PATH": f"{tests_bin}:{os.environ['PATH']}",
                "MOCK_AWS_STDOUT": "",
                "MOCK_AWS_STDERR": "",
                "MOCK_AWS_EXIT_CODE": "0",
                "MOCK_JQ_STDOUT": "",
                "MOCK_JQ_STDERR": "",
                "MOCK_JQ_EXIT_CODE": "0",
            },
        )
        read_filter, _ = build_filters()
        tool = AwsCliTool(Role.READ_ONLY, read_filter, _env=mock.env)
        mcp = FastMCP("test")
        await register(mcp, _aws_read=tool)
        async with Client(transport=mcp, elicitation_handler=mock.elicitor) as client:
            yield client, mock
        assert not mock.elicitor._queue, f"{len(mock.elicitor._queue)} elicitation step(s) were never triggered"

    def describe_run():
        async def it_rejects_mutating_commands(run_setup) -> None:
            client, mock = run_setup
            result = await client.call_tool(
                "aws_read", {"account": _ACCOUNT, "command": ["ec2", "create-instance"]}, raise_on_error=False
            )
            assert_that(result.is_error).is_true()

        async def it_rejects_blocked_flags(run_setup) -> None:
            client, mock = run_setup
            result = await client.call_tool(
                "aws_read",
                {"account": _ACCOUNT, "command": ["s3api", "list-buckets"], "flags": ["--endpoint-url=evil.com"]},
                raise_on_error=False,
            )
            assert_that(result.is_error).is_true()

        async def it_requires_user_confirmation(run_setup) -> None:
            client, mock = run_setup
            mock.elicitor.decline()
            result = await client.call_tool(
                "aws_read", {"account": _ACCOUNT, "command": ["s3api", "list-buckets"]}, raise_on_error=False
            )
            assert_that(result.is_error).is_true()

        async def it_returns_raw_aws_output(run_setup) -> None:
            client, mock = run_setup
            mock.env["MOCK_AWS_STDOUT"] = '{"Buckets": []}'
            mock.elicitor.accept()
            result = await client.call_tool(
                "aws_read", {"account": _ACCOUNT, "command": ["s3api", "list-buckets"]}, raise_on_error=False
            )
            assert_that(result.is_error).is_false()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": '{"Buckets": []}', "stderr": ""}}
            )

        async def it_filters_output_through_jq(run_setup) -> None:
            client, mock = run_setup
            mock.env["MOCK_AWS_STDOUT"] = '{"Buckets": []}'
            mock.env["MOCK_JQ_STDOUT"] = "[]"
            mock.elicitor.accept()
            result = await client.call_tool(
                "aws_read",
                {"account": _ACCOUNT, "command": ["s3api", "list-buckets"], "jq_filter": ".Buckets"},
                raise_on_error=False,
            )
            assert_that(result.is_error).is_false()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": "[]", "stderr": ""}}
            )

        async def it_falls_back_to_aws_output_when_jq_fails(run_setup) -> None:
            client, mock = run_setup
            mock.env["MOCK_AWS_STDOUT"] = '{"Buckets": []}'
            mock.env["MOCK_JQ_EXIT_CODE"] = "1"
            mock.env["MOCK_JQ_STDERR"] = "parse error"
            mock.elicitor.accept()
            result = await client.call_tool(
                "aws_read",
                {"account": _ACCOUNT, "command": ["s3api", "list-buckets"], "jq_filter": ".Buckets"},
                raise_on_error=False,
            )
            assert_that(result.is_error).is_false()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": '{"Buckets": []}', "stderr": "parse error"}}
            )

        async def it_surfaces_aws_errors(run_setup) -> None:
            client, mock = run_setup
            mock.env["MOCK_AWS_EXIT_CODE"] = "255"
            mock.env["MOCK_AWS_STDERR"] = "command not found"
            mock.elicitor.accept()
            result = await client.call_tool(
                "aws_read", {"account": _ACCOUNT, "command": ["s3api", "list-buckets"]}, raise_on_error=False
            )
            assert_that(result.is_error).is_false()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {_ACCOUNT: {"exit_status": "255", "stdout": "", "stderr": "command not found"}}
            )
