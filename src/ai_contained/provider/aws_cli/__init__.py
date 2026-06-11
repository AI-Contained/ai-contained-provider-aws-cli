"""AWS CLI provider for AI-Contained."""

from fastmcp import FastMCP

from ai_contained.provider.aws_cli.aws_cli_tool import AwsCliTool
from ai_contained.provider.aws_cli.command_filter import build_filters
from ai_contained.provider.aws_secrets.types import Role


async def register(
    mcp: FastMCP,
    *,
    _aws_read: AwsCliTool | None = None,
    _aws_write: AwsCliTool | None = None,
) -> None:
    """Register AWS CLI tools with the MCP server."""
    read_filter, write_filter = build_filters()
    aws_read = _aws_read or AwsCliTool(Role.READ_ONLY, read_filter)
    aws_write = _aws_write or AwsCliTool(Role.READ_WRITE, write_filter)

    mcp.tool(name="aws_read")(aws_read.run)
    mcp.tool(name="aws_write")(aws_write.run)
