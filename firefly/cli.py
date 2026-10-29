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
    scan.add_argument("--db", metavar="PATH", help="vulnerability database (default: $FIREFLY_DB or ~/.cache/firefly)")
    scan.add_argument("--fpdb", metavar="PATH", help="function-fingerprint database (default: $FIREFLY_FPDB or ~/.cache/firefly)")
    scan.add_argument("--no-file-inventory", action="store_true", help="don't record the per-file list in the report (disables file-level `firefly diff`)")
    scan.add_argument("--no-sbom", action="store_true", help="don't write a CycloneDX SBOM")
    scan.add_argument("--no-html", action="store_true", help="don't write the HTML report")
    scan.add_argument("--sarif", action="store_true", help="also write a SARIF file for CI (e.g. GitHub code scanning)")
    scan.add_argument("--emulate", action="store_true", help="also run binaries under qemu-user (Linux only; executes untrusted code in a sandbox)")
    scan.add_argument("--emulate-system", action="store_true", help="also attempt a full-system boot under qemu-system (Linux only)")
    _add_emulation_args(scan)
    _add_system_args(scan)
    scan.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="medium",
        help="lowest confidence shown in the console summary; reports always contain everything (default: %(default)s)",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="only write the JSON report")

    sub.add_parser("analyzers", help="list available analyzers")

    emu = sub.add_parser(
        "emulate",
        help="run firmware binaries under qemu-user in a sandbox (Linux only; executes untrusted code)",
    )
    emu.add_argument("input", help="firmware image, rootfs tarball, or extracted directory")
    emu.add_argument("-o", "--output", default="firefly-out", help="output directory (default: %(default)s)")
    emu.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1, help="parallel extraction workers")
    emu.add_argument("--backend", choices=["auto", "unblob", "binwalk"], default="auto", help="extraction backend for raw images")
    emu.add_argument("-q", "--quiet", action="store_true", help="only write the JSON report")
    emu.add_argument("--system", action="store_true", help="full-system boot under qemu-system instead of per-binary qemu-user")
    _add_emulation_args(emu)
    _add_system_args(emu)

    db = sub.add_parser("db", help="manage the offline vulnerability database")
    db_sub = db.add_subparsers(dest="db_command")
    upd = db_sub.add_parser("update", help="download the latest NVD data (verified by SHA-256)")
    upd.add_argument("--full", action="store_true", help="rebuild from all yearly feeds")
    imp = db_sub.add_parser("import", help="import local NVD JSON feeds (.json or .json.xz), e.g. for air-gapped hosts")
    imp.add_argument("files", nargs="+")
    db_sub.add_parser("info", help="show database status")
    for p in (upd, imp, db_sub.choices["info"]):
        p.add_argument("--db", metavar="PATH", help="database path")

    fpdb = sub.add_parser("fpdb", help="manage the function-fingerprint database for binary SCA")
    fpdb_sub = fpdb.add_subparsers(dest="fpdb_command")
    fpbuild = fpdb_sub.add_parser("build", help="build signatures from reference binaries described by a JSON manifest")
    fpbuild.add_argument("manifest", help="JSON manifest: [{path, product, version, vendor?, arch?}, ...]")
    fpdb_sub.add_parser("info", help="show fingerprint database status")
    for p in (fpbuild, fpdb_sub.choices["info"]):
        p.add_argument("--fpdb", metavar="PATH", help="database path")

    disc = sub.add_parser("disclose", help="prepare coordinated-disclosure advisory drafts from a scan report (never sends)")
    disc.add_argument("report", help="path to a firefly.json scan report")
    disc.add_argument("-o", "--output", help="output directory (default: <report dir>/disclosure)")
    disc.add_argument("--researcher", default="(your name) <you@example.com>", help="reporter name/contact for the advisory header")
    disc.add_argument("--vendor", help="vendor name, for contact guidance")
    disc.add_argument("--security-txt", metavar="PATH", help="a saved vendor security.txt to parse (not fetched)")
    disc.add_argument("--deadline-days", type=int, default=90, help="coordinated-disclosure window in days (default: %(default)s)")
    disc.add_argument("--min-confidence", choices=["low", "medium", "high"], default="medium", help="lowest confidence to include (default: %(default)s)")
    disc.add_argument("--include-cves", action="store_true", help="also create remediation items for already-public CVEs")

    diff = sub.add_parser("diff", help="diff two scan reports: components, findings and CVEs added/removed between two firmware builds")
    diff.add_argument("old", help="path to the older firefly.json (or a directory containing one)")
    diff.add_argument("new", help="path to the newer firefly.json (or a directory containing one)")
    diff.add_argument("-o", "--output", metavar="PATH", help="also write the diff as JSON to this path")
    diff.add_argument("--json", action="store_true", help="print the diff as JSON instead of a summary table")
    diff.add_argument("--min-confidence", choices=["low", "medium", "high"], default="medium", help="lowest finding confidence to compare (default: %(default)s)")
    diff.add_argument("--fail-on-regression", action="store_true", help="exit non-zero if the newer build adds any CVE or non-info finding (for CI)")
    return parser


def _add_emulation_args(p: argparse.ArgumentParser) -> None:
    """Emulation tuning flags shared by `scan` and `emulate`.

    The `--emulate` toggle itself lives only on `scan`; the `emulate` command
    turns emulation on unconditionally.
    """
    p.add_argument("--emulate-timeout", type=float, default=20.0, metavar="SEC", help="wall-clock timeout per binary (default: %(default)s)")
    p.add_argument("--emulate-max", type=int, default=64, metavar="N", help="max binaries to emulate (default: %(default)s)")
    p.add_argument("--emulate-arg", action="append", default=[], metavar="ARG", help="argument to pass to each emulated binary (repeatable)")
    p.add_argument("--no-emulate-sandbox", action="store_true", help="run without bubblewrap isolation (resource limits only; unsafe)")
    p.add_argument("--emulate-shim", action="store_true", help="cross-compile and inject the runtime interception shim if a toolchain is available")


def _add_system_args(p: argparse.ArgumentParser) -> None:
    """Full-system (Phase B) tuning flags, shared by `scan` and `emulate`."""
    p.add_argument("--system-timeout", type=float, default=90.0, metavar="SEC", help="full-system boot timeout (default: %(default)s)")
    p.add_argument("--system-kernel", metavar="PATH", help="kernel image to boot (else auto-detected in the image)")
    p.add_argument("--system-machine", metavar="M", help="qemu -M machine type (else a per-arch default)")
    p.add_argument("--system-dtb", metavar="PATH", help="device tree blob to pass to qemu")
    p.add_argument("--system-nic", metavar="MODEL", help="NIC device model for slirp networking")
    p.add_argument("--system-append", metavar="CMDLINE", help="kernel command line (overrides the default)")
    p.add_argument("--system-image", metavar="PATH", help="prebuilt root disk image (else one is built from the rootfs)")
    p.add_argument("--system-initrd", metavar="PATH", help="initramfs to boot (bypasses needing a disk driver in the kernel)")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "analyzers":
        from firefly.analyzers import all_analyzers

        for cls in all_analyzers():
            print(f"{cls.name:<12} {cls.description}")
        return 0

    if args.command == "db":
        return _db_command(args)

    if args.command == "fpdb":
        return _fpdb_command(args)

    if args.command == "disclose":
        return _disclose_command(args)

    if args.command == "diff":
        return _diff_command(args)

    if args.command == "scan":
        return _scan_command(args)

    if args.command == "emulate":
        return _emulate_command(args)

    build_parser().print_help()
    return 0


def _scan_command(args: argparse.Namespace) -> int:
    from firefly import sbom
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
        db_path=args.db,
        fpdb_path=args.fpdb,
        file_inventory=not args.no_file_inventory,
        emulate=args.emulate,
        emulate_timeout=args.emulate_timeout,
        emulate_max=args.emulate_max,
        emulate_sandbox=not args.no_emulate_sandbox,
        emulate_shim=args.emulate_shim,
        emulate_args=tuple(args.emulate_arg),
        emulate_system=args.emulate_system,
        emulate_system_timeout=args.system_timeout,
        emulate_kernel=args.system_kernel,
        emulate_machine=args.system_machine,
        emulate_dtb=args.system_dtb,
        emulate_nic=args.system_nic,
        emulate_append=args.system_append,
        emulate_image=args.system_image,
        emulate_initrd=args.system_initrd,
    )
    result = scan(args.input, options)
    report_path = write_json(result)
    sbom_path = None if args.no_sbom else sbom.write(result)
    extra = []
    if not args.no_html:
        from firefly import htmlreport

        extra.append(("html", htmlreport.write_result(result, os.path.join(result.workdir, "firefly.html"))))
    if args.sarif:
        from firefly import sarif
        from firefly.report import to_dict

        extra.append(("sarif", sarif.write(to_dict(result), os.path.join(result.workdir, "firefly.sarif"))))
    if args.quiet:
        print(report_path)
    else:
        print_summary(result, report_path, sbom_path, args.min_confidence)
        for label, path in extra:
            print(f"{label}: {path}")
    return 1 if any(e["stage"] == "extract" for e in result.errors) and not result.findings else 0


def _emulate_command(args: argparse.Namespace) -> int:
    """Extract + inventory + emulation only (no static analyzers)."""
    from firefly.pipeline import ScanOptions, scan
    from firefly.report import print_summary, write_json

    if not os.path.exists(args.input):
        print(f"firefly: input not found: {args.input}", file=sys.stderr)
        return 2
    options = ScanOptions(
        output_dir=args.output,
        jobs=args.jobs,
        backend=args.backend,
        run_static=False,
        emulate=not args.system,
        emulate_timeout=args.emulate_timeout,
        emulate_max=args.emulate_max,
        emulate_sandbox=not args.no_emulate_sandbox,
        emulate_shim=args.emulate_shim,
        emulate_args=tuple(args.emulate_arg),
        emulate_system=args.system,
        emulate_system_timeout=args.system_timeout,
        emulate_kernel=args.system_kernel,
        emulate_machine=args.system_machine,
        emulate_dtb=args.system_dtb,
        emulate_nic=args.system_nic,
        emulate_append=args.system_append,
        emulate_image=args.system_image,
        emulate_initrd=args.system_initrd,
    )
    result = scan(args.input, options)
    report_path = write_json(result)
    if args.quiet:
        print(report_path)
    else:
        print_summary(result, report_path, None, "low")
    return 1 if any(e["stage"] == "extract" for e in result.errors) and not result.findings else 0


def _disclose_command(args: argparse.Namespace) -> int:
    import json

    from firefly import advisory, disclosure

    if not os.path.isfile(args.report):
        print(f"firefly: report not found: {args.report}", file=sys.stderr)
        return 2
    with open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)

    out_dir = args.output or os.path.join(os.path.dirname(os.path.abspath(args.report)), "disclosure")
    adv_dir = os.path.join(out_dir, "advisories")
    os.makedirs(adv_dir, exist_ok=True)

    security_txt = None
    if args.security_txt:
        try:
            with open(args.security_txt, encoding="utf-8") as fh:
                security_txt = fh.read()
        except OSError as exc:
            print(f"firefly: cannot read security.txt: {exc}", file=sys.stderr)
            return 2

    items = disclosure.build_items(report, min_confidence=args.min_confidence, include_cves=args.include_cves)
    if not items:
        print("No disclosable findings at this confidence level.")
        return 0

    tracker_path = os.path.join(out_dir, "tracker.json")
    tracker = disclosure.update_tracker(disclosure.load_tracker(tracker_path), items, args.deadline_days)
    disclosure.save_tracker(tracker, tracker_path)

    target = os.path.basename(report.get("input", {}).get("path", "firmware"))
    discovered = tracker["updated"]
    for item in items:
        entry = tracker["items"][item.id]
        md = advisory.render_advisory(
            item,
            researcher=args.researcher,
            vendor=args.vendor,
            discovered=entry["discovered"],
            deadline=entry["deadline"],
            security_txt=security_txt,
        )
        with open(os.path.join(adv_dir, f"{item.id}.md"), "w", encoding="utf-8") as fh:
            fh.write(md)

    index = advisory.render_index(items, target=target, discovered=discovered, researcher=args.researcher)
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(index)

    print(f"Prepared {len(items)} advisory draft(s) in {out_dir}")
    print(f"  index:   {os.path.join(out_dir, 'README.md')}")
    print(f"  tracker: {tracker_path}")
    print("These are drafts. Review each one and confirm the vendor contact before sending; Firefly sends nothing.")
    return 0


def _diff_command(args: argparse.Namespace) -> int:
    import json

    from firefly import fwdiff

    try:
        old = fwdiff.load_report(args.old)
        new = fwdiff.load_report(args.new)
    except fwdiff.DiffError as exc:
        print(f"firefly: {exc}", file=sys.stderr)
        return 2

    diff = fwdiff.diff_reports(old, new, min_confidence=args.min_confidence)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(diff.to_dict(), fh, indent=2)
    if args.json:
        print(json.dumps(diff.to_dict(), indent=2))
    else:
        fwdiff.print_diff(diff)
        if args.output:
            print(f"diff: {args.output}")
    return 1 if args.fail_on_regression and diff.has_regression else 0


def _fpdb_command(args: argparse.Namespace) -> int:
    from firefly import fpdb

    path = args.fpdb or fpdb.default_fpdb_path()
    if args.fpdb_command == "build":
        if not os.path.isfile(args.manifest):
            print(f"firefly: manifest not found: {args.manifest}", file=sys.stderr)
            return 2
        try:
            info = fpdb.build_from_manifest(path, args.manifest)
        except (OSError, KeyError, ValueError) as exc:
            print(f"firefly: fingerprint build failed: {exc}", file=sys.stderr)
            return 1
    elif args.fpdb_command == "info":
        db = fpdb.FpDB.open_existing(path)
        if db is None:
            print(f"no fingerprint database at {path}; run `firefly fpdb build <manifest>`")
            return 1
        with db:
            info = db.info()
    else:
        build_parser().parse_args(["fpdb", "--help"])
        return 2
    for key, value in info.items():
        print(f"{key:<16} {value}")
    return 0


def _db_command(args: argparse.Namespace) -> int:
    from firefly import vulndb

    path = args.db or vulndb.default_db_path()
    if args.db_command == "update":
        try:
            info = vulndb.update(path, full=args.full)
        except (OSError, RuntimeError) as exc:
            print(f"firefly: database update failed: {exc}", file=sys.stderr)
            return 1
    elif args.db_command == "import":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with vulndb.VulnDB(path) as db:
            vulndb.import_files(db, args.files)
            info = db.info()
    elif args.db_command == "info":
        db = vulndb.VulnDB.open_existing(path)
        if db is None:
            print(f"no database at {path}; run `firefly db update`")
            return 1
        with db:
            info = db.info()
    else:
        build_parser().parse_args(["db", "--help"])
        return 2
    for key, value in info.items():
        print(f"{key:<16} {value}")
    return 0
