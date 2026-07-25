import json
from collections.abc import AsyncGenerator

import ai_contained.provider.trust_client as trust_client
import pytest
from assertpy import assert_that
from conftest import LocalHarness

from ai_contained.core.mcp import ProviderContext, ProviderNotLoaded
from ai_contained.core.mcp.harness import ExecResponse, Harness
from ai_contained.provider import aws_cli, aws_secrets
from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustConfig

_ACCOUNT = "123456789012"
_UNAUTHORIZED_ACCOUNT = "999999999999"
_CREDENTIAL_ENV = {"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"}


def _export_stdout(env: dict[str, str]) -> str:
    """What `aws configure export-credentials --format env` prints for these credentials."""
    return "".join(f"export {key}={value}\n" for key, value in env.items())


@pytest.fixture
async def harness() -> AsyncGenerator[LocalHarness, None]:
    accounts_json = f"""{{
        login: {{ type: "sso" }},
        accounts: {{
            "{_ACCOUNT}": {{
                name: "Test", read_profile: "test-read", write_profile: "test-write"
            }},
            "{_UNAUTHORIZED_ACCOUNT}": {{
                name: "Unauthorized", read_profile: "test-read", write_profile: "test-write"
            }},
        }},
    }}"""
    async with LocalHarness(
        env={
            "TRUST_CLIENTS": "127.0.0.1",
            "COLOR": "off",
            "EXPERIMENTAL_APPROVE_ALL_READS": "",
        }
    ) as h:
        await h.install(trust_server.provide)
        path = h.write("accounts.json5", accounts_json)
        await h.install(aws_secrets.provide, env={"AWS_ACCOUNTS_CONFIG_PATH": path})

        # trust_client's real network path can't run in-process — build its state over
        # the fake transport. raw_client() builds the app, so all routes exist by now.
        ctx = ProviderContext(h.mcp, {"TRUST_SERVERS": "aws=http://ignored"})
        h.add(trust_client.provide, await trust_client.provide(ctx, _http_client_factory=lambda _: h.raw_client()))
        await h.install(aws_cli.provide)

        # The real CredentialsManager shells out to aws — answer via shims.
        h.exec("aws").on("sts", "get-caller-identity").returns(ExecResponse(stdout=json.dumps({"Account": _ACCOUNT})))
        h.exec("aws").on("configure", "export-credentials").returns(
            ExecResponse(stdout=_export_stdout(_CREDENTIAL_ENV))
        )
        h.exec("aws").returns(ExecResponse())
        h.exec("jq").returns(ExecResponse())

        await h.aws_auth_read(_ACCOUNT)
        yield h


def describe_provide():
    async def it_exposes_read_and_write_tools(harness: LocalHarness) -> None:
        tool_names = [t.name for t in await harness.mcp.list_tools()]
        assert_that(tool_names).contains("aws_read", "aws_write")

    async def it_exposes_two_tools_only() -> None:
        async with Harness() as h:
            h.add(trust_client.provide, await TrustConfig.create(""))
            await h.install(aws_cli.provide)
            assert_that(await h.mcp.list_tools()).is_length(2)

    async def it_requires_trust_client_to_be_loaded_first() -> None:
        async with Harness() as h:
            with pytest.raises(ProviderNotLoaded):
                await h.install(aws_cli.provide)


def describe_AwsCliTool():
    def describe_run():
        async def it_rejects_mutating_commands(harness: LocalHarness) -> None:
            result = await harness.aws_read(account=_ACCOUNT, command=["ec2", "create-instance"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(
                "'ec2 create-instance': command is not recognized as read-only — use aws_write instead"
            )
            # filters must reject before exec — the command never spawned
            assert_that([c.argv[:1] for c in harness.exec("aws").calls]).does_not_contain(["ec2"])

        async def it_rejects_blocked_flags(harness: LocalHarness) -> None:
            result = await harness.aws_read(
                account=_ACCOUNT, command=["s3api", "list-buckets"], flags=["--endpoint-url=evil.com"]
            )
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(
                "'--endpoint-url=evil.com': --endpoint-url is not permitted"
            )
            assert_that([c.argv[:1] for c in harness.exec("aws").calls]).does_not_contain(["s3api"])

        async def it_requires_user_confirmation(harness: LocalHarness) -> None:
            harness.elicit.decline()
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Command declined: aws s3api list-buckets")

        async def it_includes_summary_in_elicitation_message(harness: LocalHarness) -> None:
            harness.elicit.accept(
                expect_message=(
                    f"I will run on Test({_ACCOUNT}):  (using tool: aws_read)\n"
                    "\n"
                    "    aws s3api list-buckets\n"
                    "\n"
                    "Purpose: check bucket inventory"
                )
            )
            result = await harness.aws_read(
                account=_ACCOUNT, command=["s3api", "list-buckets"], summary="check bucket inventory"
            )
            assert_that(result.is_error).is_false()

        async def it_shows_short_jq_filter_in_full(harness: LocalHarness) -> None:
            # 40 chars or fewer — shown verbatim, no truncation
            short_filter = ".Buckets | length"
            harness.elicit.accept(
                expect_message=(
                    f"I will run on Test({_ACCOUNT}):  (using tool: aws_read)\n"
                    "\n"
                    f"    aws s3api list-buckets | jq '{short_filter}'"
                )
            )
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=short_filter)
            assert_that(result.is_error).is_false()

        async def it_truncates_long_jq_filter_to_40_chars(harness: LocalHarness) -> None:
            # 78 chars — truncated to 37 chars + "..." (40 chars total)
            long_filter = "{count: (.SecretList | length), names: [.SecretList[].Name], next: .NextToken}"
            harness.elicit.accept(
                expect_message=(
                    f"I will run on Test({_ACCOUNT}):  (using tool: aws_read)\n"
                    "\n"
                    "    aws s3api list-buckets | jq '{count: (.SecretList | length), names...'"
                )
            )
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=long_filter)
            assert_that(result.is_error).is_false()

        async def it_returns_raw_aws_output(harness: LocalHarness) -> None:
            harness.exec("aws").returns(ExecResponse(stdout='{"Buckets": []}'))
            harness.elicit.accept()
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "0", "stdout": '{"Buckets": []}', "stderr": ""}}
            )

        async def it_filters_output_through_jq(harness: LocalHarness) -> None:
            harness.exec("aws").returns(ExecResponse(stdout='{"Buckets": []}'))
            harness.exec("jq").returns(ExecResponse(stdout="[]"))
            harness.elicit.accept()
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".Buckets")
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to({_ACCOUNT: {"exit_status": "0", "stdout": "[]", "stderr": ""}})

        async def it_falls_back_to_aws_output_when_jq_fails(harness: LocalHarness) -> None:
            harness.exec("aws").returns(ExecResponse(stdout='{"Buckets": []}'))
            harness.exec("jq").returns(ExecResponse(stderr="parse error", exit_code=1))
            harness.elicit.accept()
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".Buckets")
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "1", "stdout": '{"Buckets": []}', "stderr": "parse error"}}
            )

        async def it_does_not_expose_aws_credentials_to_jq(harness: LocalHarness) -> None:
            harness.exec("aws").returns(ExecResponse(stdout='{"Buckets": []}'))
            harness.elicit.accept()
            await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"], jq_filter=".")
            jq_env = harness.exec("jq").calls[0].env
            assert_that(jq_env).does_not_contain_key("AWS_ACCESS_KEY_ID")
            assert_that(jq_env).does_not_contain_key("AWS_SECRET_ACCESS_KEY")
            # positive control: the aws process itself DID receive the credentials
            aws_env = harness.exec("aws").calls[-1].env
            assert_that(aws_env["AWS_SECRET_ACCESS_KEY"]).is_equal_to(_CREDENTIAL_ENV["AWS_SECRET_ACCESS_KEY"])

        async def it_surfaces_aws_errors(harness: LocalHarness) -> None:
            harness.exec("aws").returns(ExecResponse(stderr="command not found", exit_code=255))
            harness.elicit.accept()
            result = await harness.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_false()
            assert_that(result.json()).is_equal_to(
                {_ACCOUNT: {"exit_status": "255", "stdout": "", "stderr": "command not found"}}
            )

        async def it_raises_when_aws_trust_client_is_not_configured() -> None:
            async with LocalHarness(env={"COLOR": "off"}) as h:
                h.add(trust_client.provide, await TrustConfig.create("aws="))  # explicit deny
                await h.install(aws_cli.provide)
                result = await h.aws_read(account=_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("aws trust source not configured")

        async def it_raises_tool_error_on_http_error_from_trust_client(harness: LocalHarness) -> None:
            result = await harness.aws_read(account=_UNAUTHORIZED_ACCOUNT, command=["s3api", "list-buckets"])
            assert_that(result.is_error).is_true()
            assert_that(result.json()).is_equal_to(
                {
                    "code": "NOT_AUTHORIZED",
                    "detail": f"Call aws_auth_read('{_UNAUTHORIZED_ACCOUNT}') to authenticate, then retry",
                }
            )
