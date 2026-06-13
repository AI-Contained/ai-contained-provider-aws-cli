"""Type definitions for the AWS CLI provider."""

from enum import StrEnum


class Role(StrEnum):
    """Access level used when fetching AWS credentials."""

    READ_ONLY = "ReadOnly"
    READ_WRITE = "ReadWrite"
