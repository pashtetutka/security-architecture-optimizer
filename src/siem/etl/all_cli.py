"""Compatibility entrypoint; prefer python -m siem.etl."""
from .commands.collection import main

if __name__ == "__main__":
    main()
