"""MCP tool implementation for AWS CLI execution."""

import os
from typing import TypedDict

import httpx
from fastmcp import Context
from fastmcp import tools as mcp
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_cli.command_filter import CommandFilter
from ai_contained.provider.aws_cli.piper_process import PiperProcess
from ai_contained.provider.aws_cli.types import Role
from ai_contained.trust.client.trust_config import get_trust_config


class AwsCliResponse(TypedDict):
    """JSON-serializable result of a single AWS CLI invocation."""

    exit_status: str
    stdout: str
    stderr: str


class AwsCliTool:
    """Executes AWS CLI commands on behalf of the AI, optionally piped through jq."""

    def __init__(
        self,
        role: Role,
        command_filter: CommandFilter,
    ) -> None:
        """Initialize with role and command filter."""
        self._role = role
        self._command_filter = command_filter

    @mcp.tool()
    async def run(
        self,
        ctx: Context,
        account: str,
        command: list[str],
        flags: list[str] = [],
        jq_filter: str | None = None,
        summary: str | None = None,
    ) -> dict[str, AwsCliResponse]:
        """Execute an AWS CLI command and return per-account results.

        Returns a dict keyed by account ID, each value containing
        exit_status, stdout, and stderr.
        """
        rejection = self._command_filter.rejection_command(command)
        if rejection:
            raise ToolError(rejection)

        rejection = self._command_filter.rejection_flags(flags)
        if rejection:
            raise ToolError(rejection)

        account_name, base_env, aws_env = await self._build_envs(account)

        tool_name = "aws_read" if self._role == Role.READ_ONLY else "aws_write"
        cmd_str = "aws " + " ".join(command + flags)
        if jq_filter:
            cmd_str += f" | jq '{jq_filter}'"
        msg = f"I will run the following command on {account_name}({account}): {cmd_str} (using tool: {tool_name})"
        if summary:
            msg += f"\nPurpose: {summary}"

        result = await ctx.elicit(message=msg, response_type=None)
        if result.action != "accept":
            raise ToolError(f"Command declined: {cmd_str}")
        response = await self._execute(base_env, aws_env, command, flags, jq_filter)
        return {account: response}

    async def _build_envs(self, account: str) -> tuple[str, dict[str, str], dict[str, str]]:
        """Return (account_name, base_env, aws_env) where base_env has no AWS_* vars and aws_env adds credentials."""
        base_env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}

        trust_config = get_trust_config()
        if trust_config is None:
            raise ToolError("aws trust source not configured")
        client = trust_config.get_client("aws")
        if client is None:
            raise ToolError("aws trust source not configured")

        try:
            credentials = await client.post({"account_id": account, "role": self._role.value})
        except httpx.HTTPStatusError as e:
            raise ToolError(e.response.content.decode()) from e

        aws_env = {**base_env, **credentials[account]["env"], "AWS_PAGER": ""}
        return credentials[account]["name"], base_env, aws_env

    async def _execute(
        self,
        base_env: dict[str, str],
        aws_env: dict[str, str],
        command: list[str],
        flags: list[str],
        jq_filter: str | None,
    ) -> AwsCliResponse:
        aws_args = ["aws"] + command + ["--output=json"] + flags

        async with PiperProcess(aws_args, env=aws_env) as aws:
            if jq_filter is not None:
                async with PiperProcess(["jq", jq_filter], env=base_env, upstream=aws) as jq:
                    jq_response = await jq.wait()
                aws_response = await aws.wait()
                if jq_response["exit_code"] == 0:
                    return AwsCliResponse(
                        exit_status=str(jq_response["exit_code"]),
                        stdout=jq_response["stdout"],
                        stderr=aws_response["stderr"],
                    )
                return AwsCliResponse(
                    exit_status=str(jq_response["exit_code"]),
                    stdout=aws_response["stdout"],
                    stderr=jq_response["stderr"],
                )
            else:
                aws_response = await aws.wait()
                return AwsCliResponse(
                    exit_status=str(aws_response["exit_code"]),
                    stdout=aws_response["stdout"],
                    stderr=aws_response["stderr"],
                )
