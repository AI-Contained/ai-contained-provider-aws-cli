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


@dataclass
class CommandFilter:
    """Ordered rule chain for classifying AWS CLI commands and flags."""

    command_rules: list[CommandRule]
    flag_rules: list[CommandRule]
    default: CommandPolicy
    default_reason: str = ""

    def rejection_command(self, command: list[str]) -> str | None:
        """Return rejection reason if command is not permitted, else None."""
        raise NotImplementedError

    def rejection_flags(self, flags: list[str]) -> str | None:
        """Return rejection reason if any flag is not permitted, else None."""
        raise NotImplementedError


def build_filters() -> tuple[CommandFilter, CommandFilter]:
    """Return (read_filter, write_filter) using production rule definitions."""
    raise NotImplementedError
