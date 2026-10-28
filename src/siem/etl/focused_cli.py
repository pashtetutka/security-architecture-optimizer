"""Compatibility entrypoint; prefer python -m siem.etl."""
from .commands.normalization import main

if __name__ == "__main__":
    main()
