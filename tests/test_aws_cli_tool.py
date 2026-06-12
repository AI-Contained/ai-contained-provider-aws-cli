import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client

from ai_contained.core.mcp.testing import Elicitor, WrapCallToolResult
from ai_contained.provider.aws_cli import register
from ai_contained.provider.aws_cli.aws_cli_tool import AwsCliTool
from ai_contained.provider.aws_cli.command_filter import build_filters
from ai_contained.provider.aws_secrets import register as aws_secrets_register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.types import Role
from ai_contained.trust import server as trust_server
from ai_contained.trust.client.trust_config import init_trust_config, reset_trust_config
from ai_contained.trust.server.trust_store import get_trust_store
from conftest import tool_client


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

    class MockCredentialsManager:
        async def validate(self, role, account):
            raise NotImplementedError

        async def login(self, ctx, role, account):
            raise NotImplementedError

        async def fetch_credentials(self, role, account):
            raise NotImplementedError

    def _return_responses(*values):
        it = iter(values)

        async def _fn(*args, **kwargs):
            val = next(it)
            if isinstance(val, Exception):
                raise val
            return val

        return _fn

    @dataclass
    class Mock:
        elicitor: Elicitor
        credentials_manager: MockCredentialsManager
        auth_read: AwsAuthTool

    @pytest.fixture
    async def setup(monkeypatch):
        credential = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration=None,
        )
        accounts_json = f"""{{
            login: {{ type: "sso" }},
            accounts: {{ "{_ACCOUNT}": {{
                name: "Test", read_profile: "test-read", write_profile: "test-write"
            }} }},
        }}"""
        tests_bin = str(Path(__file__).parent / "bin")
        monkeypatch.setenv("PATH", f"{tests_bin}:{os.environ['PATH']}")
        monkeypatch.setenv("MOCK_AWS_STDOUT", "")
        monkeypatch.setenv("MOCK_AWS_STDERR", "")
        monkeypatch.setenv("MOCK_AWS_EXIT_CODE", "0")
        monkeypatch.setenv("MOCK_JQ_STDOUT", "")
        monkeypatch.setenv("MOCK_JQ_STDERR", "")
        monkeypatch.setenv("MOCK_JQ_EXIT_CODE", "0")

        accounts = Accounts(accounts_json)
        credentials_manager = MockCredentialsManager()
        auth_read = AwsAuthTool(Role.READ_ONLY, accounts, credentials_manager)
        auth_write = AwsAuthTool(Role.READ_WRITE, accounts, credentials_manager)

        get_trust_store().reset()
        trust_server.get_trust_config().reset("127.0.0.1")
        mcp = FastMCP("test")
        await trust_server.register(mcp)
        await aws_secrets_register(mcp, _accounts=accounts, _auth_read=auth_read, _auth_write=auth_write)

        credential_transport = httpx.ASGITransport(app=mcp.http_app(), client=("127.0.0.1", 50000))
        await init_trust_config(
            "aws=http://ignored/aws/secret",
            factory=lambda url: httpx.AsyncClient(transport=credential_transport, base_url="http://ignored"),
        )

        read_filter, _ = build_filters()
        await register(mcp, _aws_read=AwsCliTool(Role.READ_ONLY, read_filter))

        mock = Mock(elicitor=Elicitor(), credentials_manager=credentials_manager, auth_read=auth_read)
        mock.auth_read.authorize(_ACCOUNT)
        mock.credentials_manager.fetch_credentials = _return_responses(credential)
        async with Client(transport=mcp, elicitation_handler=mock.elicitor) as client:
            @tool_client(client)
            async def aws_read(): pass
            try:
                yield aws_read, mock
            finally:
                reset_trust_config()
        assert not mock.elicitor._queue, f"{len(mock.elicitor._queue)} elicitation step(s) were never triggered"

    @pytest.fixture
    async def no_trust_setup():
        reset_trust_config()
        elicitor = Elicitor()
        read_filter, _ = build_filters()
        mcp = FastMCP("test")
        await register(mcp, _aws_read=AwsCliTool(Role.READ_ONLY, read_filter))
        async with Client(transport=mcp, elicitation_handler=elicitor) as client:
            @tool_client(client)
            async def aws_read(): pass
            yield aws_read, elicitor
        reset_trust_config()
        assert not elicitor._queue, f"{len(elicitor._queue)} elicitation step(s) were never triggered"

    def describe_run():
        async def it_rejects_mutating_commands(setup) -> None:
            aws_read, mock = setup
            result = await aws_read(account=_ACCOUNT, command=["ec2", "create-instance"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(
                "'ec2 create-instance': command is not recognized as read-only — use aws_write instead"
            )

        async def it_rejects_blocked_flags(setup) -> None:
            aws_read, mock = setup
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], flags=["--endpoint-url=evil.com"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(
                "'--endpoint-url=evil.com': --endpoint-url is not permitted"
            )

        async def it_requires_user_confirmation(setup) -> None:
            aws_read, mock = setup
            mock.elicitor.decline()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Command declined: aws s3api list-buckets")

        async def it_includes_summary_in_elicitation_message(setup) -> None:
            aws_read, mock = setup
            mock.elicitor.accept(
                expect_message=(
                    "I will run the following command: aws s3api list-buckets (using tool: aws_read)\n"
                    "Purpose: check bucket inventory"
                )
            )
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], summary="check bucket inventory")
            assert_that(result.is_error).is_false()

        async def it_returns_raw_aws_output(setup, monkeypatch) -> None:
            aws_read, mock = setup
            monkeypatch.setenv("MOCK_AWS_STDOUT", '{"Buckets": []}')
            mock.elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": '{"Buckets": []}', "stderr": ""}}
            )

        async def it_filters_output_through_jq(setup, monkeypatch) -> None:
            aws_read, mock = setup
            monkeypatch.setenv("MOCK_AWS_STDOUT", '{"Buckets": []}')
            monkeypatch.setenv("MOCK_JQ_STDOUT", "[]")
            mock.elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".Buckets")
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": "[]", "stderr": ""}}
            )

        async def it_falls_back_to_aws_output_when_jq_fails(setup, monkeypatch) -> None:
            aws_read, mock = setup
            monkeypatch.setenv("MOCK_AWS_STDOUT", '{"Buckets": []}')
            monkeypatch.setenv("MOCK_JQ_EXIT_CODE", "1")
            monkeypatch.setenv("MOCK_JQ_STDERR", "parse error")
            mock.elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".Buckets")
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "1", "stdout": '{"Buckets": []}', "stderr": "parse error"}}
            )

        async def it_does_not_expose_aws_credentials_to_jq(setup, monkeypatch) -> None:
            aws_read, mock = setup
            monkeypatch.setenv("MOCK_AWS_STDOUT", '{"Buckets": []}')
            with tempfile.NamedTemporaryFile(mode="r", suffix=".env", delete=False) as f:
                env_dump = f.name
            monkeypatch.setenv("MOCK_JQ_ENV_DUMP", env_dump)
            mock.elicitor.accept()
            await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".")
            jq_env = Path(env_dump).read_text()
            assert_that(jq_env).does_not_contain("AKID")
            assert_that(jq_env).does_not_contain("SECRET")

        async def it_surfaces_aws_errors(setup, monkeypatch) -> None:
            aws_read, mock = setup
            monkeypatch.setenv("MOCK_AWS_EXIT_CODE", "255")
            monkeypatch.setenv("MOCK_AWS_STDERR", "command not found")
            mock.elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "255", "stdout": "", "stderr": "command not found"}}
            )

        async def it_raises_when_trust_config_is_not_initialized(no_trust_setup) -> None:
            aws_read, elicitor = no_trust_setup
            elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("aws trust source not configured")

        async def it_raises_when_aws_trust_client_is_not_configured(no_trust_setup) -> None:
            aws_read, elicitor = no_trust_setup
            await init_trust_config("aws=", factory=lambda url: httpx.AsyncClient())
            elicitor.accept()
            result = await aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("aws trust source not configured")

        async def it_raises_tool_error_on_http_error_from_trust_client(setup) -> None:
            aws_read, mock = setup
            mock.elicitor.accept()
            invalid_account="000000000000"
            result = await aws_read(account=invalid_account, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.json()).is_equal_to({
                "code": "UNKNOWN_ACCOUNT",
                "detail": f"Account '{invalid_account}' is not configured",
            })
