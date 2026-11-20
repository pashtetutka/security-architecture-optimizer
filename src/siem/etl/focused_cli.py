"""Compatibility entrypoint; prefer python -m siem.etl."""
from .commands.normalization import main
import sys

if __name__ == "__main__":
    sys.exit(main())
