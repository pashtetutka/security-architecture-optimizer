"""A consistent UTF-8 output contract for CLI terminals and redirected streams."""
import sys


def configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is not None:
            reconfigure(encoding='utf-8')
