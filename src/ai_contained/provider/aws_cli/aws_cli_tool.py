"""MCP tool implementation for AWS CLI execution."""

from typing import TypedDict

from fastmcp import Context
from fastmcp import tools as mcp

from ai_contained.provider.aws_cli.command_filter import CommandFilter
from ai_contained.provider.aws_secrets.types import Role


class AwsCliResponse(TypedDict):
    exit_status: str
    stdout: str
    stderr: str


class AwsCliTool:
    """Executes AWS CLI commands on behalf of the AI, optionally piped through jq."""

    def __init__(
        self,
        role: Role,
        command_filter: CommandFilter,
        _env: dict[str, str] | None = None,
    ) -> None:
        self._role = role
        self._command_filter = command_filter
        self._env = _env

    @mcp.tool()
    async def run(
        self,
        ctx: Context,
        account: str,
        command: list[str],
        jq_filter: str | None = None,
        summary: str | None = None,
    ) -> dict[str, AwsCliResponse]:
        """Execute an AWS CLI command and return per-account results.

        Returns a dict keyed by account ID, each value containing
        exit_status, stdout, and stderr.
        """
        raise NotImplementedError
