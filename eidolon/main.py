import argparse
import sys

from eidolon import config
from eidolon.core import runner
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


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-agent",
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
    return p


def main():
    config.validate()

    parser = _build_parser()
    args = parser.parse_args()

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
    )
    logger.info("Pipeline complete (scan_id=%s)", result.scan_id)


if __name__ == "__main__":
    main()
