"""Eidolon — local, privacy-first, MCP-native OSINT exposure scanner."""

from importlib import metadata as _metadata

try:
    #: package release version (pyproject version when installed)
    __version__ = _metadata.version("eidolon-osint")
except _metadata.PackageNotFoundError:  # running from a source checkout
    __version__ = "0.0.0+source"
