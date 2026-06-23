"""Entry point: ``python -m eidolon.mcp`` runs the server over stdio."""

from eidolon.mcp.server import mcp


def main() -> None:
    mcp.run()  # stdio transport by default


if __name__ == "__main__":
    main()
