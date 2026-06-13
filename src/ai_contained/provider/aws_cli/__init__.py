"""AWS CLI provider for AI-Contained."""

from fastmcp import FastMCP

from ai_contained.provider.aws_cli.aws_cli_tool import AwsCliTool
from ai_contained.provider.aws_cli.command_filter import build_filters
from ai_contained.provider.aws_secrets.types import Role

_AWS_READ_DESCRIPTION = """\
Execute a read-only AWS CLI command on a previously authenticated account.

Call aws_auth_read before using this tool. The user will be prompted to confirm
each command before it runs.

Parameters
----------
  account   12-digit AWS account ID (must have been authenticated with aws_auth_read).
  command   AWS CLI subcommand tokens, e.g. ["ec2", "describe-instances"].
  flags     Optional extra flags in --key=value form, e.g. ["--region=eu-west-1"].
            Do NOT include --output; JSON output is always used.
  jq_filter Optional jq expression applied to stdout, e.g. ".Reservations[].Instances[].InstanceId".
  summary   One-sentence description shown to the user in the confirmation prompt.

Return value (JSON):
  { "<account_id>": { "exit_status": "<0 or non-zero>", "stdout": "<json string>", "stderr": "<string>" } }

Notes:
  - Only read-only commands are permitted; write operations will be rejected.
  - --output is not permitted; use jq_filter to reshape output instead.
  - Prefer this over aws_write — use the least-privileged tool that satisfies the request.
"""

_AWS_WRITE_DESCRIPTION = """\
Execute a read-write AWS CLI command on a previously authenticated account.

Call aws_auth_write before using this tool. The user will be prompted to confirm
each command before it runs.

Parameters
----------
  account   12-digit AWS account ID (must have been authenticated with aws_auth_write).
  command   AWS CLI subcommand tokens, e.g. ["s3", "cp", "file.txt", "s3://bucket/"].
  flags     Optional extra flags in --key=value form, e.g. ["--region=eu-west-1"].
            Do NOT include --output; JSON output is always used.
  jq_filter Optional jq expression applied to stdout.
  summary   One-sentence description shown to the user in the confirmation prompt.

Return value (JSON):
  { "<account_id>": { "exit_status": "<0 or non-zero>", "stdout": "<json string>", "stderr": "<string>" } }

Notes:
  - This tool can create, update, and delete AWS resources. Only use it when write access is required.
  - --output is not permitted; use jq_filter to reshape output instead.
  - Prefer aws_read when you only need to inspect resources.
"""


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

    mcp.tool(name="aws_read", description=_AWS_READ_DESCRIPTION)(aws_read.run)
    mcp.tool(name="aws_write", description=_AWS_WRITE_DESCRIPTION)(aws_write.run)
