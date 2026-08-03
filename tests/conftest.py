from typing import Any

from assertpy import assert_that

from ai_contained.core.mcp.harness import Harness, ToolResult


class LocalHarness(Harness):
    """Harness with the aws-cli and aws-secrets tools callable directly."""

    async def aws_auth_read(self, account_id: str) -> Any:
        """Call the aws_auth_read tool for the account, accepting its elicitation."""
        self.elicit.accept()
        async with self.client() as c:
            result = await c.tool("aws_auth_read")(account_id=account_id)
            assert_that(result.is_error).is_false()
            return result.json()

    async def aws_read(self, **kwargs: Any) -> ToolResult:
        """Call the aws_read tool; the caller inspects the result."""
        async with self.client() as c:
            return await c.tool("aws_read")(**kwargs)
