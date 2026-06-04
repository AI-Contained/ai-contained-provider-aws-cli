"""Command filtering for the AWS CLI provider."""

from dataclasses import dataclass
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

    def check(self, tokens: list[str]) -> CommandPolicy | None:
        """Return policy if all patterns match tokens positionally, else None."""
        raise NotImplementedError


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
