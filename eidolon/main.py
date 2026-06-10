import argparse
import re
import sys

from eidolon import config
from eidolon.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

# ── Validation / sanitization ─────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_PHONE_RE = re.compile(r"[\d\s\-().+]+")


def _validate_email(value: str) -> str:
    v = value.strip().lower()
    if not _EMAIL_RE.match(v):
        raise argparse.ArgumentTypeError(f"Invalid email address: {value!r}")
    return v


def _validate_phone(value: str) -> str:
    digits = re.sub(r"[^\d+]", "", value.strip())
    if len(digits) < 7:
        raise argparse.ArgumentTypeError(f"Phone number too short: {value!r}")
    # Normalise to E.164-ish: ensure leading +
    if not digits.startswith("+"):
        # assume US if 10 digits, otherwise keep as-is
        digits = f"+1{digits}" if len(digits) == 10 else f"+{digits}"
    return digits


def _validate_name(value: str) -> str:
    v = " ".join(value.strip().split())  # collapse whitespace
    if len(v) < 2:
        raise argparse.ArgumentTypeError(f"Name too short: {value!r}")
    # Strip any stray punctuation except hyphens and apostrophes
    v = re.sub(r"[^\w\s\-']", "", v)
    return v


def _validate_state(value: str) -> str:
    v = value.strip()
    if not v:
        raise argparse.ArgumentTypeError("State cannot be empty")
    return v


def _validate_city(value: str) -> str:
    v = " ".join(value.strip().split())
    v = re.sub(r"[^\w\s\-']", "", v)
    if not v:
        raise argparse.ArgumentTypeError("City cannot be empty")
    return v


def _validate_zip(value: str) -> str:
    v = re.sub(r"\D", "", value.strip())
    if len(v) not in (5, 9):
        raise argparse.ArgumentTypeError(f"Zip code must be 5 or 9 digits: {value!r}")
    return v[:5]  # store as 5-digit


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

    # Build a structured raw_input string that intake_node can parse.
    # Format: "type:value" lines so intake_node skips regex guessing.
    parts = []
    if args.email:
        parts.append(f"email:{args.email}")
    if args.phone:
        parts.append(f"phone:{args.phone}")
    if args.name:
        parts.append(f"name:{args.name}")
    if args.city:
        parts.append(f"city:{args.city}")
    if args.state:
        parts.append(f"state:{args.state}")
    if args.zip:
        parts.append(f"zip:{args.zip}")
    raw_input = "\n".join(parts)

    logger.info("Starting OSINT pipeline")
    if args.email:
        logger.info("  email: %s", args.email)
    if args.phone:
        logger.info("  phone: %s", args.phone)
    if args.name:
        logger.info("  name:  %s", args.name)
    if args.city:
        logger.info("  city:  %s", args.city)
    if args.state:
        logger.info("  state: %s", args.state)
    if args.zip:
        logger.info("  zip:   %s", args.zip)

    from eidolon.agent.graph import build_graph
    from eidolon.core.models import PipelineState

    graph = build_graph()
    initial_state = PipelineState(raw_input=raw_input)
    graph.invoke(initial_state)
    logger.info("Pipeline complete")


if __name__ == "__main__":
    main()
