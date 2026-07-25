"""MCP tool implementation for AWS CLI execution."""

import hashlib
from typing import TypedDict

import httpx
from fastmcp import Context
from fastmcp import tools as mcp
from fastmcp.exceptions import ToolError

from ai_contained.core.mcp import Environ
from ai_contained.provider.aws_cli.command_filter import CommandFilter
from ai_contained.provider.aws_cli.piper_process import PiperProcess
from ai_contained.provider.aws_cli.types import Role
from ai_contained.trust.client import TrustClient


class AwsCliResponse(TypedDict):
    """JSON-serializable result of a single AWS CLI invocation."""

    exit_status: str
    stdout: str
    stderr: str


class _Color:
    """ANSI colorizer for elicitation messages. Disabled via COLOR != 'ascii'."""

    def __init__(self, environ: Environ) -> None:
        """Read the COLOR toggle once from the given environment."""
        self._enabled = environ.get("COLOR", "ascii") == "ascii"

    def _wrap(self, ansi: str, text: str) -> str:
        if not self._enabled:
            return text
        return f"\033[{ansi}m{text}\033[0m"

    def role(self, name: str) -> str:
        """Green for aws_read, red for aws_write."""
        return self._wrap("32" if name == "aws_read" else "31", name)

    def id(self, account: str) -> str:
        """Dim gray — de-emphasizes the 12-digit account ID next to its human name."""
        return self._wrap("38;5;245", account)

    def name(self, account_name: str) -> str:
        """Deterministic per-name hue, hashed into the 6×6×6 color cube (codes 17–231)."""
        code = (hashlib.blake2b(account_name.encode(), digest_size=1).digest()[0] % 215) + 17
        return self._wrap(f"38;5;{code}", account_name)


class AwsCliTool:
    """Executes AWS CLI commands on behalf of the AI, optionally piped through jq."""

    def __init__(
        self,
        environ: Environ,
        trust: TrustClient | None,
        role: Role,
        command_filter: CommandFilter,
    ) -> None:
        """Initialize from the container's launch env with the aws trust client, for the given role."""
        self._role = role
        self._command_filter = command_filter
        self._trust = trust
        self._color = _Color(environ)
        self._approve_all_reads = bool(environ.get("EXPERIMENTAL_APPROVE_ALL_READS"))
        self._base_env = {k: v for k, v in environ.items() if not k.startswith("AWS_")}

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
            displayed_jq = jq_filter if len(jq_filter) <= 40 else jq_filter[:37] + "..."
            cmd_str += f" | jq '{displayed_jq}'"
        msg = (
            f"I will run on {self._color.name(account_name)}({self._color.id(account)}):  "
            f"(using tool: {self._color.role(tool_name)})\n\n    {cmd_str}"
        )
        if summary:
            msg += f"\n\nPurpose: {summary}"

        auto_approve = self._role == Role.READ_ONLY and self._approve_all_reads
        if not auto_approve:
            result = await ctx.elicit(message=msg, response_type=None)
            if result.action != "accept":
                raise ToolError(f"Command declined: {cmd_str}")
        response = await self._execute(base_env, aws_env, command, flags, jq_filter)
        return {account: response}

    async def _build_envs(self, account: str) -> tuple[str, dict[str, str], dict[str, str]]:
        """Return (account_name, base_env, aws_env) where base_env has no AWS_* vars and aws_env adds credentials."""
        if self._trust is None:
            raise ToolError("aws trust source not configured")

        try:
            credentials = await self._trust.post({"account_id": account, "role": self._role.value})
        except httpx.HTTPStatusError as e:
            raise ToolError(e.response.content.decode()) from e

        aws_env = {**self._base_env, **credentials[account]["env"], "AWS_PAGER": ""}
        return credentials[account]["name"], self._base_env, aws_env

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
