"""``python -m dcpstudio`` entry point.

With no arguments (or only Qt arguments) this launches the desktop GUI. When
the first argument is a CLI subcommand it dispatches to :mod:`dcpstudio.cli`,
so ``python -m dcpstudio discover`` works without a separate script.
"""

from __future__ import annotations

import sys

from .cli import CLI_COMMANDS


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and (
        arguments[0] in CLI_COMMANDS or arguments[0] in ("-h", "--help", "--version")
    ):
        from .cli import main as cli_main

        return cli_main(arguments)

    from .gui.app import run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
