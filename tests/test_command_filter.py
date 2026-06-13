import pytest
from assertpy import assert_that

from ai_contained.provider.aws_cli.command_filter import CommandFilter, CommandPolicy, CommandRule, build_filters

ALLOW = CommandPolicy.ALLOW
DENY = CommandPolicy.DENY


def describe_CommandRule():
    def describe_check():
        def it_fires_when_all_patterns_match() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check(["ec2", "describe-instances"])).is_equal_to(ALLOW)

        def it_does_not_fire_on_a_mismatch() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check(["s3api", "describe-instances"])).is_none()

        def it_does_not_fire_when_only_some_patterns_match() -> None:
            rule = CommandRule(DENY, [".*", "wait", ".*"])
            assert_that(rule.check(["ec2", "describe-instances", "foo"])).is_none()

        def it_tolerates_extra_tokens_beyond_the_patterns() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check(["ec2", "describe-instances", "--region=us-east-1"])).is_equal_to(ALLOW)

        def it_matches_the_full_token_not_a_substring() -> None:
            rule = CommandRule(ALLOW, ["ec2", "list-.*"])
            assert_that(rule.check(["ec2", "xlist-buckets"])).is_none()

        def it_does_not_match_when_token_has_trailing_content() -> None:
            rule = CommandRule(ALLOW, ["dynamodb", "query"])
            assert_that(rule.check(["dynamodb", "query"])).is_equal_to(ALLOW)
            assert_that(rule.check(["dynamodb", "query-something"])).is_none()

        def it_applies_regex_patterns() -> None:
            rule = CommandRule(DENY, ["--endpoint-url(?:=.*)?"])
            assert_that(rule.check(["--endpoint-url=https://evil.com"])).is_equal_to(DENY)
            assert_that(rule.check(["--endpoint-url"])).is_equal_to(DENY)
            assert_that(rule.check(["--endpoint-url-something-else"])).is_none()
            assert_that(rule.check(["--region=us-east-1"])).is_none()

        def it_enforces_minimum_token_count() -> None:
            rule = CommandRule(ALLOW, [".*", "wait", ".*"])
            assert_that(rule.check([])).is_none()
            assert_that(rule.check(["ec2", "wait"])).is_none()
            assert_that(rule.check(["ec2", "wait", "instance-running"])).is_equal_to(ALLOW)
            assert_that(rule.check(["ec2", "wait", "instance-running", "container-id"])).is_equal_to(ALLOW)


def describe_CommandFilter():
    def describe_rejection_command():
        def it_rejects_when_a_command_token_matches_a_deny_rule() -> None:
            f = CommandFilter(
                ALLOW,
                command_rules=[CommandRule(DENY, ["--.*"], reason="flags not permitted before service")],
            )
            assert_that(f.rejection_command(["--debug", "describe-instances"])).is_equal_to(
                "'--debug': flags not permitted before service"
            )
            assert_that(f.rejection_command(["ec2", "describe-instances"])).is_none()

        def it_rejects_when_a_strict_deny_rule_fires() -> None:
            f = CommandFilter(
                ALLOW,
                command_strict_rules=[CommandRule(DENY, ["configure", ".*"], reason="not permitted")],
            )
            assert_that(f.rejection_command(["configure", "list"])).is_equal_to("'configure list': not permitted")
            assert_that(f.rejection_command(["ec2", "help"])).is_none()

        def it_permits_when_a_strict_allow_rule_fires() -> None:
            f = CommandFilter(
                DENY,
                default_reason="not recognized as read-only",
                command_strict_rules=[CommandRule(ALLOW, ["ec2", "describe-.*"])],
            )
            assert_that(f.rejection_command(["ec2", "describe-instances"])).is_none()
            assert_that(f.rejection_command(["ec2", "run-instances"])).is_equal_to(
                "'ec2 run-instances': not recognized as read-only"
            )

        def it_stops_at_the_first_matching_strict_rule() -> None:
            f = CommandFilter(
                DENY,
                default_reason="unknown command",
                command_strict_rules=[
                    CommandRule(ALLOW, ["sts", "get-caller-identity"]),
                    CommandRule(DENY, ["sts", ".*"], reason="sts not permitted"),
                ],
            )
            assert_that(f.rejection_command(["sts", "get-caller-identity"])).is_none()
            assert_that(f.rejection_command(["sts", "assume-role"])).is_equal_to("'sts assume-role': sts not permitted")

        def it_applies_default_deny_when_no_strict_rule_matches() -> None:
            f = CommandFilter(DENY, default_reason="unknown command")
            assert_that(f.rejection_command(["ec2", "describe-instances"])).is_equal_to(
                "'ec2 describe-instances': unknown command"
            )

        def it_applies_default_allow_when_no_strict_rule_matches() -> None:
            f = CommandFilter(ALLOW)
            assert_that(f.rejection_command(["ec2", "run-instances"])).is_none()

        def it_runs_command_token_scan_before_strict_rules() -> None:
            f = CommandFilter(
                ALLOW,
                command_rules=[CommandRule(DENY, ["--.*"], reason="flags not permitted before service")],
                command_strict_rules=[CommandRule(ALLOW, ["--debug", ".*"])],
            )
            assert_that(f.rejection_command(["--debug", "describe-instances"])).is_equal_to(
                "'--debug': flags not permitted before service"
            )

    def describe_rejection_flags():
        def it_rejects_when_a_flag_matches_a_deny_rule() -> None:
            f = CommandFilter(
                ALLOW,
                flag_rules=[CommandRule(DENY, ["--endpoint-url(?:=.*)?"], reason="not permitted")],
            )
            assert_that(f.rejection_flags(["--endpoint-url=evil.com"])).is_equal_to(
                "'--endpoint-url=evil.com': not permitted"
            )
            assert_that(f.rejection_flags(["--endpoint-url"])).is_equal_to("'--endpoint-url': not permitted")
            assert_that(f.rejection_flags(["--region=us-east-1"])).is_none()

        def it_scans_all_flag_tokens_not_just_the_first() -> None:
            f = CommandFilter(
                ALLOW,
                flag_rules=[CommandRule(DENY, [".*file[b]?://.*"], reason="filesystem not permitted")],
            )
            assert_that(f.rejection_flags(["--region=us-east-1", "--body=file://secret.json"])).is_equal_to(
                "'--body=file://secret.json': filesystem not permitted"
            )
            assert_that(f.rejection_flags(["--region=us-east-1", "--output=json"])).is_none()

        def it_permits_an_empty_flag_list() -> None:
            f = CommandFilter(
                ALLOW,
                flag_rules=[CommandRule(DENY, ["--endpoint-url(?:=.*)?"], reason="not permitted")],
            )
            assert_that(f.rejection_flags([])).is_none()

        def it_raises_when_a_flag_rule_has_allow_policy() -> None:
            with pytest.raises(NotImplementedError):
                CommandFilter(ALLOW, flag_rules=[CommandRule(ALLOW, [".*"], reason="")])

        def it_raises_when_a_command_rule_has_allow_policy() -> None:
            with pytest.raises(NotImplementedError):
                CommandFilter(ALLOW, command_rules=[CommandRule(ALLOW, [".*"], reason="")])


def describe_build_filters():
    class Case:
        def __init__(
            self,
            policy: CommandPolicy,
            command: list[str],
            flags: list[str] = [],
        ) -> None:
            self.policy = policy
            self.command = command
            self.flags = flags

        @property
        def id(self) -> str:
            parts = " ".join(self.command + self.flags)
            return f"!{parts}" if self.policy == DENY else parts

    @pytest.fixture
    def read() -> CommandFilter:
        return build_filters()[0]

    @pytest.fixture
    def write() -> CommandFilter:
        return build_filters()[1]

    COMMON_CASES = [
        # flags are not permitted in the service-name position
        Case(DENY, ["--debug", "ec2"]),
        # codeartifact — get-authorization-token leaks registry credentials
        Case(DENY, ["codeartifact", "get-authorization-token"]),
        # cognito-identity — get-credentials-for-identity returns AWS credentials for a Cognito identity pool
        Case(DENY, ["cognito-identity", "get-credentials-for-identity"]),
        # configure — blocked entirely; subcommands irrelevant
        Case(DENY, ["configure", "list"]),
        # ec2 — flag-level denials applied regardless of command
        Case(DENY, ["ec2", "describe-instances"], flags=["--body=file://input.json"]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--body=fileb://input.json"]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--endpoint-url=https://evil.com"]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--output=text"]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--output="]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--output"]),
        Case(DENY, ["ec2", "describe-instances"], flags=["--template-file=foo.yaml"]),
        # help is always allowed
        Case(ALLOW, ["help"]),
        Case(ALLOW, ["ec2", "help"]),
        Case(ALLOW, ["ec2", "describe-instances", "help"]),
        # ...except when you trying to subvert the system
        # Case(DENY,  ["help"], flags=["--debug=true"),  # TODO:  Is this possible?
        Case(ALLOW, ["help"], flags=["--region=plant-earth-1"]),
        Case(DENY, ["help"], flags=["--ca-bundle=evilcorp.bundle"]),
        Case(DENY, ["help"], flags=["--cli-auto-prompt"]),  # Our tool does not handle prompting from stdin
        Case(DENY, ["help"], flags=["--debug"]),  # debugging might leak sensitive information
        Case(DENY, ["help", "--debug"]),
        Case(DENY, ["help"], flags=["--endpoint-url=https://evil.com"]),
        Case(DENY, ["help"], flags=["--no-sign-request"]),
        Case(DENY, ["help"], flags=["--no-verify-ssl"]),
        Case(DENY, ["help"], flags=["--profile=SystemRoot"]),
        # ecr — both credential retrieval commands blocked (v1 and v2 APIs)
        Case(DENY, ["ecr", "get-authorization-token"]),
        Case(DENY, ["ecr", "get-login-password"]),
        # ecs — execute-command opens an interactive shell inside a running container
        Case(DENY, ["ecs", "execute-command"]),
        # eks — get-token returns a short-lived cluster auth token
        Case(DENY, ["eks", "get-token"]),
        # sso — get-role-credentials returns temporary AWS credentials for an SSO role assignment
        Case(DENY, ["sso", "get-role-credentials"]),
        # ssm — start-session opens an interactive shell session into an EC2 instance
        Case(DENY, ["ssm", "start-session"]),
        # sts — session/role credential commands blocked; get-caller-identity handled per filter
        Case(DENY, ["sts", "assume-role"]),
        Case(DENY, ["sts", "get-session-token"]),
    ]

    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(c, id=c.id)
            for c in COMMON_CASES
            + [
                # cloudformation
                Case(ALLOW, ["cloudformation", "list-stacks"]),
                # dynamodb — query/scan explicitly allowed; write commands blocked
                Case(ALLOW, ["dynamodb", "query"]),
                Case(ALLOW, ["dynamodb", "scan"]),
                # ec2 — read-only verbs allowed; mutating verbs blocked
                Case(ALLOW, ["ec2", "describe-instances"]),
                Case(DENY, ["ec2", "run-instances"]),
                Case(DENY, ["ec2", "terminate-instances"]),
                Case(ALLOW, ["ec2", "wait", "instance-running"]),
                # iam
                Case(DENY, ["iam", "create-user"]),
                Case(ALLOW, ["iam", "get-user"]),
                # s3
                Case(ALLOW, ["s3", "ls", "s3://my-bucket"]),
                Case(DENY, ["s3", "ls"], flags=["s3://my-bucket"]),
                # s3api
                Case(ALLOW, ["s3api", "list-buckets"]),
                Case(DENY, ["s3api", "put-object"]),
                # lambda — invoke is a mutating operation; use aws_write instead
                Case(DENY, ["lambda", "invoke"]),
                # secretsmanager — get-secret-value returns the actual plaintext secret value
                Case(DENY, ["secretsmanager", "get-secret-value"]),
                # ssm — entire service blocked in read; even read-like subcommands can expose sensitive state
                Case(DENY, ["ssm", "get-parameter"]),
                Case(DENY, ["ssm", "list-commands"]),
                Case(DENY, ["ssm", "send-command"]),
                # sts — get-caller-identity is the one allowed sts command in read
                Case(ALLOW, ["sts", "get-caller-identity"]),
            ]
        ],
    )
    def it_applies_read_policy(read: CommandFilter, case: Case) -> None:
        result = read.rejection_command(case.command) or read.rejection_flags(case.flags)
        if case.policy == ALLOW:
            assert_that(result).is_none()
        else:
            assert_that(result).is_not_none()

    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(c, id=c.id)
            for c in COMMON_CASES
            + [
                # configure — single token bypasses the 2-pattern ["configure", ".*"] deny rule
                Case(DENY, ["configure"]),
                # dynamodb — scan is a read-like operation but write defaults to ALLOW
                Case(ALLOW, ["dynamodb", "scan"]),
                # ec2 — mutating verbs allowed in write
                Case(ALLOW, ["ec2", "run-instances"]),
                Case(ALLOW, ["ec2", "terminate-instances"]),
                # iam
                Case(ALLOW, ["iam", "create-user"]),
                # lambda — invoke is allowed in write
                Case(ALLOW, ["lambda", "invoke"]),
                # s3api
                Case(ALLOW, ["s3api", "put-object"]),
                # ssm — all subcommands allowed in write
                Case(ALLOW, ["ssm", "get-parameter"]),
                Case(ALLOW, ["ssm", "send-command"]),
                # sts — single token bypasses the 2-pattern ["sts", ".*"] deny rule; no write exemption for get-caller-identity
                Case(DENY, ["sts"]),
                Case(DENY, ["sts", "get-caller-identity"]),
            ]
        ],
    )
    def it_applies_write_policy(write: CommandFilter, case: Case) -> None:
        result = write.rejection_command(case.command) or write.rejection_flags(case.flags)
        if case.policy == ALLOW:
            assert_that(result).is_none()
        else:
            assert_that(result).is_not_none()
