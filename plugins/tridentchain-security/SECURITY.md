# Security — TridentChain Claude Plugin

## Threat model (local MCP)

- **Trust boundary:** User's machine and chosen `project_path`.
- **MCP server:** Stdio process `tridentchain-mcp` — no inbound network listener.
- **Secrets:** Never embedded in the plugin; optional `NVD_API_KEY`, `GITHUB_TOKEN` via user environment only.

## Tool behavior

| Tool | Writes local files? | Network |
|------|---------------------|---------|
| `scan_project` | Yes (`output_dir` reports) | Advisory API queries |
| `scan_full` | Yes | Advisory API queries |
| `validate_after_patch` | No | No |

## User guidance

- Scope `--project-path` / `project_path` to the workspace root.
- Do not paste API keys into Claude chat.
- Review generated reports before sharing externally.

## Reporting vulnerabilities

Report security issues via GitHub Issues (private disclosure preferred for sensitive findings):

https://github.com/DevInder1/supply-chain-scanner-public/security

## Reviewer notes (Anthropic)

- PyPI packages: `tridentchain-security`, `tridentchain-mcp`
- Install: `pip install "tridentchain-security>=0.1.2" tridentchain-mcp`
- Test: `scan_project` on a small repo with `package.json`
- No OAuth; local connector only
