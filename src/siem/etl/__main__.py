"""Run the ETL with python -m siem.etl."""
import sys
from .cli import main

if __name__ == '__main__':
    sys.exit(main())
