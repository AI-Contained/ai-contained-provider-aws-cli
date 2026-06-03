import pytest
from fastmcp import FastMCP

from ai_contained.provider.aws_cli import register


@pytest.mark.asyncio
async def test_register_runs() -> None:
    server = FastMCP("test")
    await register(server)
