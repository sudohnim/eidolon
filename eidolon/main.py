import argparse
import sys

from eidolon import config
from eidolon.core import batch, runner
from eidolon.core.authorization import Authorization
from eidolon.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

# ── Validation / sanitization ─────────────────────────────────────────────────
# The normalization rules live in eidolon.core.runner (shared with the MCP
# server). These thin wrappers just translate ValueError into argparse's error.


def _argtype(fn):
    def wrapper(value: str) -> str:
        try:
            return fn(value)
        except ValueError as e:
            raise argparse.ArgumentTypeError(str(e))

    return wrapper


_validate_email = _argtype(runner.normalize_email)
_validate_phone = _argtype(runner.normalize_phone)
_validate_name = _argtype(runner.normalize_name)
_validate_state = _argtype(runner.normalize_state)
_validate_city = _argtype(runner.normalize_city)
_validate_zip = _argtype(runner.normalize_zip)


def _validate_concurrency(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--max-concurrency must be an integer")
    if n < 1:
        raise argparse.ArgumentTypeError("--max-concurrency must be >= 1")
    return n


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eidolon",
        description="Local privacy OSINT scanner. At least one input flag is required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --email target@example.com
  python main.py --email target@example.com --phone +14155550100
  python main.py --name "John Smith" --state CA
  python main.py --name "John Smith" --city "San Francisco" --state CA
  python main.py --email target@example.com --name "John Smith" \
                 --state NY --phone +14155550100
  python main.py --targets-file targets.txt --max-concurrency 3

targets.txt format: one target per line, "key:value" tokens separated by ';'
(values may contain spaces). Unknown keys are dropped with a warning.
  email:target@example.com
  name:John Smith;state:CA
  phone:+14155550100;name:Jane Doe
""",
    )
    p.add_argument(
        "--email", metavar="ADDRESS", type=_validate_email, help="Target email address"
    )
    p.add_argument(
        "--phone", metavar="NUMBER", type=_validate_phone, help="Target phone number"
    )
    p.add_argument(
        "--name", metavar="FULLNAME", type=_validate_name, help="Target full name"
    )
    p.add_argument(
        "--city",
        metavar="CITY",
        type=_validate_city,
        help="Target city (used with --name for broker search)",
    )
    p.add_argument(
        "--state",
        metavar="STATE",
        type=_validate_state,
        help="Target state, e.g. CA or 'California' (required with --name)",
    )
    p.add_argument(
        "--zip",
        metavar="ZIP",
        type=_validate_zip,
        help="Target zip code (used with --name for broker search)",
    )
    p.add_argument(
        "--targets-file",
        metavar="FILE",
        help="Path to a targets file (one target per line, see epilog) for batch scans",
    )
    p.add_argument(
        "--max-concurrency",
        metavar="N",
        type=_validate_concurrency,
        default=3,
        help="Concurrent scans when running --targets-file (default: 3)",
    )
    p.add_argument(
        "--authorized-by",
        metavar="OPERATOR",
        required=True,
        help="Operator attesting this scan is authorized (required; audit-logged)",
    )
    p.add_argument(
        "--reason",
        metavar="REASON",
        required=True,
        help="Why this target is being scanned (required; audit-logged)",
    )
    return p


def _run_batch(args: argparse.Namespace) -> None:
    """--targets-file path: parse + scan every target concurrently."""
    try:
        with open(args.targets_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as e:
        logger.error("cannot read targets file %s: %s", args.targets_file, e)
        sys.exit(1)

    targets: list[dict[str, str]] = []
    target_lines: list[int] = []
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        target = batch.parse_target_line(line)
        if not target:
            logger.warning("targets-file line %d: no valid keys, skipped", lineno)
            continue
        targets.append(target)
        target_lines.append(lineno)

    if not targets:
        logger.error("targets file %s contained no valid targets", args.targets_file)
        sys.exit(1)

    # per-line fields must already satisfy the name/location rule per target
    for lineno, target in zip(target_lines, targets):
        if "name" in target and not any(
            k in target for k in ("city", "state", "zip_code")
        ):
            logger.error(
                "targets-file line %d: --name target needs at least one of "
                "city/state/zip",
                lineno,
            )
            sys.exit(1)

    logger.info(
        "Batch scan: %d targets, max_concurrency=%d", len(targets), args.max_concurrency
    )
    states = batch.run_batch(
        targets,
        args.max_concurrency,
        authorization=Authorization(operator=args.authorized_by, reason=args.reason),
    )
    for state in states:
        logger.info(
            "  complete scan_id=%s target=%r findings=%d",
            state.run_id,
            state.raw_input,
            len(state.findings),
        )


def main():
    config.validate()

    parser = _build_parser()
    args = parser.parse_args()

    if args.targets_file:
        input_flags = [
            args.email,
            args.phone,
            args.name,
            args.city,
            args.state,
            args.zip,
        ]
        if any(input_flags):
            parser.print_help()
            print(
                "\nError: --targets-file cannot be combined with "
                "single-target flags (--email/--phone/--name/--city/--state/--zip)."
            )
            sys.exit(1)
        _run_batch(args)
        return

    if not any([args.email, args.phone, args.name]):
        parser.print_help()
        print("\nError: at least one of --email, --phone, or --name is required.")
        sys.exit(1)

    # --name requires at least one location flag for broker searches to be useful
    if args.name and not any([args.city, args.state, args.zip]):
        parser.print_help()
        print(
            "\nError: --name requires at least one location flag "
            "(--city, --state, or --zip)."
        )
        print('  Example: --name "John Smith" --state CA')
        sys.exit(1)

    # Location flags only make sense alongside --name
    if any([args.city, args.state, args.zip]) and not args.name:
        print(
            "Warning: --city/--state/--zip have no effect without --name. Continuing."
        )

    logger.info("Starting OSINT pipeline")
    for label, value in (
        ("email", args.email),
        ("phone", args.phone),
        ("name", args.name),
        ("city", args.city),
        ("state", args.state),
        ("zip", args.zip),
    ):
        if value:
            logger.info("  %-5s: %s", label, value)

    result = runner.run_scan(
        email=args.email,
        phone=args.phone,
        name=args.name,
        city=args.city,
        state=args.state,
        zip_code=args.zip,
        authorization=Authorization(operator=args.authorized_by, reason=args.reason),
    )
    logger.info("Pipeline complete (scan_id=%s)", result.scan_id)


if __name__ == "__main__":
    main()
