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
    raise NotImplementedError
