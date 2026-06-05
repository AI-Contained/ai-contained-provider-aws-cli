import pytest
from assertpy import assert_that

from ai_contained.provider.aws_cli.command_filter import CommandFilter, CommandPolicy, CommandRule

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
        def it_rejects_when_a_deny_rule_fires() -> None:
            f = CommandFilter(
                command_rules=[CommandRule(DENY, ["configure", ".*"], reason="not permitted")],
                flag_rules=[],
                default=ALLOW,
            )
            assert_that(f.rejection_command(["configure", "list"])).is_equal_to("'configure list': not permitted")
            assert_that(f.rejection_command(["ec2", "help"])).is_none()

        def it_permits_when_an_allow_rule_fires() -> None:
            f = CommandFilter(
                command_rules=[CommandRule(ALLOW, ["ec2", "describe-.*"])],
                flag_rules=[],
                default=DENY,
                default_reason="not recognized as read-only",
            )
            assert_that(f.rejection_command(["ec2", "describe-instances"])).is_none()
            assert_that(f.rejection_command(["ec2", "run-instances"])).is_equal_to(
                "'ec2 run-instances': not recognized as read-only"
            )

        def it_stops_at_the_first_matching_rule() -> None:
            f = CommandFilter(
                command_rules=[
                    CommandRule(ALLOW, ["sts", "get-caller-identity"]),
                    CommandRule(DENY, ["sts", ".*"], reason="sts not permitted"),
                ],
                flag_rules=[],
                default=DENY,
                default_reason="unknown command",
            )
            assert_that(f.rejection_command(["sts", "get-caller-identity"])).is_none()
            assert_that(f.rejection_command(["sts", "assume-role"])).is_equal_to("'sts assume-role': sts not permitted")

        def it_applies_default_deny_when_no_rule_matches() -> None:
            f = CommandFilter(
                command_rules=[],
                flag_rules=[],
                default=DENY,
                default_reason="unknown command",
            )
            assert_that(f.rejection_command(["ec2", "describe-instances"])).is_equal_to(
                "'ec2 describe-instances': unknown command"
            )

        def it_applies_default_allow_when_no_rule_matches() -> None:
            f = CommandFilter(command_rules=[], flag_rules=[], default=ALLOW)
            assert_that(f.rejection_command(["ec2", "run-instances"])).is_none()

        def it_rejects_when_command_has_fewer_than_two_tokens() -> None:
            f = CommandFilter(command_rules=[], flag_rules=[], default=ALLOW)
            assert_that(f.rejection_command(["ec2"])).is_equal_to("'ec2': command must include a service and operation")
            assert_that(f.rejection_command([])).is_equal_to("'': command must include a service and operation")

    def describe_rejection_flags():
        def it_rejects_when_a_flag_matches_a_deny_rule() -> None:
            f = CommandFilter(
                command_rules=[],
                flag_rules=[CommandRule(DENY, ["--endpoint-url(?:=.*)?"], reason="not permitted")],
                default=ALLOW,
            )
            assert_that(f.rejection_flags(["--endpoint-url=evil.com"])).is_equal_to(
                "'--endpoint-url=evil.com': not permitted"
            )
            assert_that(f.rejection_flags(["--endpoint-url"])).is_equal_to("'--endpoint-url': not permitted")
            assert_that(f.rejection_flags(["--region=us-east-1"])).is_none()

        def it_scans_all_flag_tokens_not_just_the_first() -> None:
            f = CommandFilter(
                command_rules=[],
                flag_rules=[CommandRule(DENY, [".*file[b]?://.*"], reason="filesystem not permitted")],
                default=ALLOW,
            )
            assert_that(f.rejection_flags(["--region=us-east-1", "--body=file://secret.json"])).is_equal_to(
                "'--body=file://secret.json': filesystem not permitted"
            )
            assert_that(f.rejection_flags(["--region=us-east-1", "--output=json"])).is_none()

        def it_raises_when_a_flag_rule_has_allow_policy() -> None:
            with pytest.raises(NotImplementedError):
                CommandFilter(
                    command_rules=[],
                    flag_rules=[CommandRule(ALLOW, [".*"], reason="")],
                    default=ALLOW,
                )

        def it_permits_an_empty_flag_list() -> None:
            f = CommandFilter(
                command_rules=[],
                flag_rules=[CommandRule(DENY, ["--endpoint-url(?:=.*)?"], reason="not permitted")],
                default=ALLOW,
            )
            assert_that(f.rejection_flags([])).is_none()
