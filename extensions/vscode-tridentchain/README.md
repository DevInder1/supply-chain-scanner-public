# TridentChain Security — VS Code Extension

Anthropic-ecosystem-aligned supply-chain scanning for VS Code.

## Architecture

```text
VS Code extension
    ├─ preferMcp: true  →  tridentchain-mcp (stdio MCP)
    │                      └─ execute_tool(scan_project | scan_full | validate_after_patch)
    └─ fallback         →  tridentchain-security CLI
```

Same tools and schemas as the [Claude plugin](../../plugins/tridentchain-security/) and [Cursor MCP](../../docs/CURSOR_SETUP.md).

## Prerequisites

```bash
pip3 install "tridentchain-security>=0.1.1" tridentchain-mcp
```

## Development

```bash
npm install
npm run compile
```

Press **F5** to launch Extension Development Host.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `tridentchain.preferMcp` | `true` | Use `tridentchain-mcp` before CLI |
| `tridentchain.mcp.command` | `tridentchain-mcp` | MCP server binary |
| `tridentchain.cli.command` | `tridentchain-security` | CLI fallback |
| `tridentchain.outputDir` | `.tridentchain-out` | Report output directory |

## License

MIT
