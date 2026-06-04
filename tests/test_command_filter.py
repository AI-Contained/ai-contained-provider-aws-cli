from assertpy import assert_that

from ai_contained.provider.aws_cli.command_filter import CommandPolicy, CommandRule

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

        def it_does_not_fire_when_tokens_are_fewer_than_patterns() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check(["ec2"])).is_none()

        def it_does_not_fire_against_empty_tokens() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check([])).is_none()

        def it_tolerates_extra_tokens_beyond_the_patterns() -> None:
            rule = CommandRule(ALLOW, ["ec2", "describe-.*"])
            assert_that(rule.check(["ec2", "describe-instances", "--region=us-east-1"])).is_equal_to(ALLOW)

        def it_matches_the_full_token_not_a_substring() -> None:
            rule = CommandRule(ALLOW, ["ec2", "list-.*"])
            assert_that(rule.check(["ec2", "xlist-buckets"])).is_none()

        def it_works_with_a_single_pattern() -> None:
            rule = CommandRule(DENY, ["--endpoint-url(?:=.*)?"])
            assert_that(rule.check(["--endpoint-url=evil.com"])).is_equal_to(DENY)

        def it_applies_regex_patterns() -> None:
            rule = CommandRule(DENY, ["--endpoint-url(?:=.*)?"])
            assert_that(rule.check(["--endpoint-url=https://evil.com"])).is_equal_to(DENY)
            assert_that(rule.check(["--endpoint-url"])).is_equal_to(DENY)
            assert_that(rule.check(["--endpoint-url-something-else"])).is_none()
            assert_that(rule.check(["--region=us-east-1"])).is_none()

        def it_enforces_minimum_token_count() -> None:
            rule = CommandRule(ALLOW, [".*", "wait", ".*"])
            assert_that(rule.check(["ec2", "wait"])).is_none()
            assert_that(rule.check(["ec2", "wait", "instance-running"])).is_equal_to(ALLOW)
            assert_that(rule.check(["ec2", "wait", "instance-running", "container-id"])).is_equal_to(ALLOW)
