"""Collect threat reports from the checked source registry."""
import sys

from source_registry import load_sources, get_enabled_sources
from source_driver import collect_sources, parse_args
from parsers.threat_intel_parsers import get_parser


def main():
    args = parse_args("threat")
    try:
        sources = get_enabled_sources(load_sources(args.config))
        return collect_sources(args, sources, get_parser)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] Invalid threat source configuration: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
