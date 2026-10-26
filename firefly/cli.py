"""Command line interface: ``firefly scan <image>``."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from firefly import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="firefly", description="Fast, safe static analysis of firmware images")
    parser.add_argument("--version", action="version", version=f"firefly {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="analyse a firmware image, root filesystem tarball or directory")
    scan.add_argument("input", help="firmware image, rootfs tarball, or extracted directory")
    scan.add_argument("-o", "--output", default="firefly-out", help="output directory (default: %(default)s)")
    scan.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1, help="parallel workers (default: CPU count)")
    scan.add_argument("--backend", choices=["auto", "unblob", "binwalk"], default="auto", help="extraction backend for raw images")
    scan.add_argument("--extract-depth", type=int, default=10, help="maximum recursion depth for extraction")
    scan.add_argument("--extract-timeout", type=int, default=3600, help="extraction timeout in seconds")
    scan.add_argument("--only", action="append", metavar="ANALYZER", help="run only this analyzer (repeatable)")
    scan.add_argument("--skip", action="append", default=[], metavar="ANALYZER", help="skip this analyzer (repeatable)")
    scan.add_argument("-q", "--quiet", action="store_true", help="only write the JSON report")

    sub.add_parser("analyzers", help="list available analyzers")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "analyzers":
        from firefly.analyzers import all_analyzers

        for cls in all_analyzers():
            print(f"{cls.name:<12} {cls.description}")
        return 0

    if args.command == "scan":
        from firefly.pipeline import ScanOptions, scan
        from firefly.report import print_summary, write_json

        if not os.path.exists(args.input):
            print(f"firefly: input not found: {args.input}", file=sys.stderr)
            return 2
        options = ScanOptions(
            output_dir=args.output,
            jobs=args.jobs,
            backend=args.backend,
            extract_depth=args.extract_depth,
            extract_timeout=args.extract_timeout,
            only=args.only,
            skip=args.skip,
        )
        result = scan(args.input, options)
        report_path = write_json(result)
        if args.quiet:
            print(report_path)
        else:
            print_summary(result, report_path)
        return 1 if any(e["stage"] == "extract" for e in result.errors) and not result.findings else 0

    build_parser().print_help()
    return 0
