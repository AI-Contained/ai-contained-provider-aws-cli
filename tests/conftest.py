from ai_contained.core.mcp.testing import WrapCallToolResult


def tool_client(client):
    def decorator(fn):
        async def _call(**kwargs) -> WrapCallToolResult:
            return WrapCallToolResult(**vars(await client.call_tool(fn.__name__, kwargs, raise_on_error=False)))

        return _call

    return decorator
