<p align="center">
  <img src="assets/logo.png" alt="Eidolon" width="160">
</p>

# Eidolon

Eidolon is a privacy-first approach to finding and understanding your digital footprint. The stack uses OSINT tools to gather information based on your search parameters, then a **local** LLM compiles it into a report. The LLM runs on your machine, so no data ever reaches an external service or leaves your box — you own your data.

## What it does

- Aggregates ~25 OSINT sources — breaches, leaked credentials, data brokers, account enumeration, public records, phone/email intel, exposed hosts — into a single risk report.
- Maps findings to **MITRE ATT&CK** so you see what an attacker could actually do with what's exposed.
- Flags **AI-training exposure** (which platforms may train on your data, and how to opt out).
- Risk scoring and the leaked-credential dossier are **deterministic** — built from scan state, not the LLM — so the report survives an LLM hiccup. The model only writes narrative.
- Outputs Markdown, PDF, and JSON.

## MCP-native

Eidolon runs as an [MCP](https://modelcontextprotocol.io) server, so you can drive it from any MCP client (Claude Desktop, Claude Code) — scan a target, list past scans, and read reports conversationally. It runs locally over stdio; your data never leaves the box.

Tools: `scan_target`, `list_scans`, `get_report`, `reveal_credentials`. The leaked-credential dossier (which includes plaintext passwords from breach dumps) is **redacted by default** and only returned when you explicitly call `reveal_credentials`.

## Requirements

- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com) for the local LLM: `ollama pull llama3.1:8b`
- A running [SpiderFoot](https://github.com/smicallef/spiderfoot) instance (optional — Eidolon degrades gracefully if it's unreachable)
- API keys — see [`.env.example`](.env.example). HIBP, Apify, and Scrapfly are required; the rest are optional and skip gracefully.

## Quickstart

```bash
git clone <your-repo-url> eidolon && cd eidolon
uv sync
cp .env.example .env        # fill in your keys

# scan yourself from the CLI
uv run eidolon --email you@example.com

# or run the MCP server (stdio)
uv run eidolon-mcp
```

### Use from Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eidolon": {
      "command": "uv",
      "args": ["run", "eidolon-mcp"],
      "cwd": "/absolute/path/to/eidolon"
    }
  }
}
```

`cwd` matters — Eidolon loads `.env` from the working directory, so live scans pick up your keys.

## How it works

A LangGraph pipeline: `intake → wave 1 scans → wave 2 scans → MITRE mapping → correlation → analysis → report`. Both the CLI and the MCP server call the same `run_scan()` core; reads go through a small repository layer. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the architecture and where it's headed (stateful history, continuous monitoring).

## Intended use

Eidolon is for scanning **yourself**, or targets you are **explicitly authorized** to assess (authorized security testing, your own footprint). It surfaces real secrets, including plaintext passwords from breach dumps. **Do not use it to profile or surveil people without their consent.** You are responsible for complying with the terms of the data sources you configure and with applicable law.

## License

[AGPL-3.0](LICENSE). If you run a modified version as a network service, you must offer users its source.
