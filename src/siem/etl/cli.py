"""Single command-line entrypoint for the SIEM ETL."""
from __future__ import annotations

import argparse
import sys

from .commands import collection, normalization, review

COMMANDS = {
    'check': (normalization.main, 'Create a local HTML overview and run project tests'),
    'crawl': (collection.main, 'Collect official documents or replay local snapshots'),
    'status': (collection.main, 'Show collection status by vendor'),
    'quality': (collection.main, 'Audit collected evidence'),
    'normalize': (normalization.main, 'Build the typed catalog from saved snapshots'),
    'report': (normalization.main, 'Show catalog readiness and limitations'),
    'enrich-registry': (normalization.main, 'Add registered official document URLs'),
    'rusiem': (review.main, 'Extract the RuSIEM source list'),
    'match': (review.main, 'Match inventory sources against extracted evidence'),
    'pdf-candidates': (review.main, 'Extract PDF candidates for manual review'),
    'assess': (collection.main, 'Run the existing experimental applicability assessment'),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description='SIEM documentation ETL')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for command, (_, description) in COMMANDS.items():
        # The handler owns its arguments and help, avoiding duplicated definitions.
        subparsers.add_parser(command, add_help=False, help=description)
    args, remaining = parser.parse_known_args(sys.argv[1:] if argv is None else argv)
    handler, _ = COMMANDS[args.command]
    return handler([args.command, *remaining])


if __name__ == '__main__':
    sys.exit(main())
