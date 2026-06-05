"""Command filtering for the AWS CLI provider."""

import re
from dataclasses import dataclass, field
from enum import StrEnum


class CommandPolicy(StrEnum):
    """Allow/deny verdict for a command rule or filter default."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class CommandRule:
    """A single pattern-based rule mapping a command shape to a policy."""

    policy: CommandPolicy
    patterns: list[str]
    reason: str = ""
    _compiled: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p) for p in self.patterns]

    def check(self, tokens: list[str]) -> CommandPolicy | None:
        """Return policy if all patterns match tokens positionally, else None."""
        if len(tokens) < len(self._compiled):
            return None
        # zip() pairs up elements from two iterables by position, stopping at the shortest one:
        #   zip(["a", "b", "c"], [1, 2, 3]) → [("a", 1), ("b", 2), ("c", 3)]
        #   zip(["a", "b"],      [1, 2, 3]) → [("a", 1), ("b", 2)]  # stops at shortest
        for pattern, token in zip(self._compiled, tokens):
            if not pattern.fullmatch(token):
                return None
        return self.policy


class CommandFilter:
    """Ordered rule chain for classifying AWS CLI commands and flags."""

    def __init__(
        self,
        default: CommandPolicy,
        default_reason: str = "",
        command_rules: list[CommandRule] = [],
        command_strict_rules: list[CommandRule] = [],
        flag_rules: list[CommandRule] = [],
    ) -> None:
        for rule in command_rules:
            if rule.policy == CommandPolicy.ALLOW:
                raise NotImplementedError("command_rules do not support ALLOW policy — token scanning is deny-only")
        for rule in flag_rules:
            if rule.policy == CommandPolicy.ALLOW:
                raise NotImplementedError("flag_rules do not support ALLOW policy — flag scanning is deny-only")
        self.default = default
        self.default_reason = default_reason
        self.command_rules = command_rules
        self.command_strict_rules = command_strict_rules
        self.flag_rules = flag_rules

    def _rejection_scan(self, tokens: list[str], rules: list[CommandRule]) -> str | None:
        """Scan each token against each deny rule, return first rejection or None."""
        for token in tokens:
            for rule in rules:
                if rule.check([token]) == CommandPolicy.DENY:
                    return f"'{token}': {rule.reason}"
        return None

    def rejection_command(self, command: list[str]) -> str | None:
        """Return rejection reason if command is not permitted, else None."""
        if rejection := self._rejection_scan(command, self.command_rules):
            return rejection
        label = " ".join(command)
        for rule in self.command_strict_rules:
            policy = rule.check(command)
            if policy == CommandPolicy.DENY:
                return f"'{label}': {rule.reason}"
            if policy == CommandPolicy.ALLOW:
                return None
        if self.default == CommandPolicy.ALLOW:
            return None
        return f"'{label}': {self.default_reason}"

    def rejection_flags(self, flags: list[str]) -> str | None:
        """Return rejection reason if any flag is not permitted, else None."""
        return self._rejection_scan(flags, self.flag_rules)


def build_filters() -> tuple[CommandFilter, CommandFilter]:
    """Return (read_filter, write_filter) using production rule definitions."""
    ALLOW = CommandPolicy.ALLOW
    DENY = CommandPolicy.DENY

    shared = CommandFilter(
        ALLOW,
        command_rules=[
            CommandRule(DENY, ["--.*"], reason="flags are not permitted as commands"),
        ],
        flag_rules=[
            CommandRule(DENY, ["(?!--).+"],                  reason="flags must begin with '--'"),
            CommandRule(DENY, ["--ca-bundle(?:=.*)?"],       reason="CA bundle replacement is not permitted"),
            CommandRule(DENY, ["--cli-auto-prompt(?:=.*)?"], reason="interactive prompting is not permitted"),
            CommandRule(DENY, ["--debug(?:=.*)?"],           reason="debug output may leak credentials"),
            CommandRule(DENY, ["--endpoint-url(?:=.*)?"],    reason="--endpoint-url is not permitted"),
            CommandRule(DENY, ["--no-sign-request"],         reason="unsigned requests are not permitted"),
            CommandRule(DENY, ["--no-verify-ssl"],           reason="disabling TLS verification is not permitted"),
            CommandRule(DENY, ["--profile(?:=.*)?"],         reason="profile switching is not permitted"),
            CommandRule(DENY, [".*file[b]?://.*"],           reason="filesystem references are not permitted"),
            CommandRule(DENY, [".+-file=.*"],                reason="filesystem flags are not permitted"),
        ],
    )

    help_strict_rules = [
        CommandRule(ALLOW, ["help"]),
        CommandRule(ALLOW, [".*", "help"]),
        CommandRule(ALLOW, [".*", ".*", "help"]),
    ]

    write = CommandFilter(
        ALLOW,
        command_rules=shared.command_rules,
        command_strict_rules=[
            # credential-leaking commands — blocked regardless of read/write intent
            CommandRule(DENY, ["cognito-identity", "get-credentials-for-identity"], reason="returns AWS credentials for a Cognito identity"),
            CommandRule(DENY, ["codeartifact",     "get-authorization-token"],      reason="returns registry auth token"),
            CommandRule(DENY, ["ecr",              "get-authorization-token"],      reason="returns Docker registry credentials (v1 API)"),
            CommandRule(DENY, ["ecr",              "get-login-password"],           reason="returns Docker registry credentials"),
            CommandRule(DENY, ["ecs",              "execute-command"],              reason="executes arbitrary commands in a container"),
            CommandRule(DENY, ["eks",              "get-token"],                   reason="returns cluster auth token"),
            CommandRule(DENY, ["secretsmanager",   "get-secret-value"],            reason="returns plaintext secret value"),
            CommandRule(DENY, ["sso",              "get-role-credentials"],        reason="returns temporary AWS credentials"),
            CommandRule(DENY, ["ssm",              "start-session"],               reason="opens an interactive shell session"),
            # service-level blocks — both single-token and subcommand forms
            CommandRule(DENY, ["configure"],        reason="configure is not permitted"),
            CommandRule(DENY, ["configure", ".*"],  reason="configure is not permitted"),
            CommandRule(DENY, ["sts"],              reason="sts is not permitted except get-caller-identity"),
            CommandRule(DENY, ["sts",       ".*"],  reason="sts is not permitted except get-caller-identity"),
            *help_strict_rules,
        ],
        flag_rules=shared.flag_rules,
    )

    read = CommandFilter(
        DENY,
        default_reason="command is not recognized as read-only — use aws_write instead",
        command_rules=shared.command_rules,
        command_strict_rules=[
            CommandRule(ALLOW, ["sts", "get-caller-identity"]),
            *write.command_strict_rules,
            CommandRule(DENY,  ["ssm", ".*"], reason="ssm is not permitted in read — use aws_write instead"),
            CommandRule(ALLOW, [".*", "check-.*"]),
            CommandRule(ALLOW, [".*", "describe-.*"]),
            CommandRule(ALLOW, [".*", "filter-.*"]),
            CommandRule(ALLOW, [".*", "get-.*"]),
            CommandRule(ALLOW, [".*", "head-.*"]),
            CommandRule(ALLOW, [".*", "list-.*"]),
            CommandRule(ALLOW, [".*", "lookup-.*"]),
            CommandRule(ALLOW, [".*", "scan-.*"]),
            CommandRule(ALLOW, [".*", "search-.*"]),
            CommandRule(ALLOW, [".*", "show-.*"]),
            CommandRule(ALLOW, [".*", "wait", ".*"]),
            CommandRule(ALLOW, ["dynamodb", "query"]),
            CommandRule(ALLOW, ["dynamodb", "scan"]),
            CommandRule(ALLOW, ["s3",       "ls"]),
        ],
        flag_rules=shared.flag_rules,
    )

    return read, write
