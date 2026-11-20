"""Compatibility entrypoint; prefer python -m siem.etl."""
from .commands.collection import main
import sys

if __name__ == "__main__":
    sys.exit(main())
