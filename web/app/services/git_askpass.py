#!/usr/bin/env python3
"""GIT_ASKPASS helper. Token lives in the clone subprocess env only."""

from __future__ import annotations

import os
import sys


USERNAME_ENV = "STRIX_GIT_ASKPASS_USERNAME"
PASSWORD_ENV = "STRIX_GIT_ASKPASS_PASSWORD"  # noqa: S105


def answer(prompt: str) -> str:
    if "username" in prompt.lower():
        return os.environ.get(USERNAME_ENV, "")
    return os.environ.get(PASSWORD_ENV, "")


def main() -> None:
    sys.stdout.write(answer(" ".join(sys.argv[1:])))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
