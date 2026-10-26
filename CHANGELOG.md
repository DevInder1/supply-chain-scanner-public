# Changelog

All notable changes to **TridentChain Security** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

Two packages ship from this repo:

- `tridentchain-security` — the scanner engine and CLI
- `tridentchain-mcp` — the stdio MCP server that exposes the scanner to AI clients

Each release notes which package versions it covers.

---

## [0.1.5] — 2026-07-29

**`tridentchain-mcp` 0.1.5** (hotfix) · `tridentchain-security` unchanged at 0.1.4

### Fixed

- Pin `mcp[cli]>=1.6.0,<2` to work around the upstream `mcp` package shipping v2.0.0, which restructured imports and removed `mcp.server.fastmcp`. Every fresh install of `tridentchain-mcp==0.1.4` was failing at import time with `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`. No behavioural changes in the server; 33/33 tests still pass.

### Published

- PyPI `tridentchain-mcp` 0.1.5
- MCP Registry `io.github.DevInder1/tridentchain-security` 0.1.5 (`isLatest: true`)
- GHCR `ghcr.io/devinder1/tridentchain-mcp:0.1.5` and `:latest` (multi-arch, public)
- Glama release 0.1.5

---

## [0.1.4] — 2026-06-09

**`tridentchain-security` 0.1.4** · **`tridentchain-mcp` 0.1.4**

### Added

- Seven Claude Code plugin skills covering the full scan-triage-remediate workflow:
  - `/tridentchain-security:quick-scan` — fast cached-only project scan
  - `/tridentchain-security:scan` — full live project scan
  - `/tridentchain-security:scan-full` — project + system packages + IDE extensions
  - `/tridentchain-security:why` — explain why a package is flagged
  - `/tridentchain-security:fix-plan` — EPSS/KEV-prioritised remediation
  - `/tridentchain-security:validate-fixes` — confirm fixes after upgrades
  - `/tridentchain-security:supply-chain-scan` — generic entry (backward-compat alias)
- Dockerfile at repo root for containerised runtime.
- GitHub Actions workflow to publish multi-arch container images to GHCR on every `v*` tag.
- GitHub repo topics (`mcp`, `supply-chain`, `osv`, `cve`, etc.) and credibility badges on both READMEs.

### Changed

- MCP tool descriptions rewritten to surface the real differentiators: EPSS exploit probability ranking, CISA KEV presence, and multi-surface coverage (project + system + IDE). Improves model tool selection on ambiguous prompts like "scan my machine".
- Plugin manifest description expanded to lead with coverage breadth.

### Published

- PyPI `tridentchain-security` 0.1.4, `tridentchain-mcp` 0.1.4
- MCP Registry 0.1.4
- GHCR `ghcr.io/devinder1/tridentchain-mcp:0.1.4`

---

## [0.1.3] — 2026-05-26

**`tridentchain-security` 0.1.3** · **`tridentchain-mcp` 0.1.3**

### Fixed

- Version-range false positives. The matcher previously treated the floor of a range expression (`requests>=2.31.0`) as if it were the pinned installed version, producing phantom CVE hits against the floor version. Range expressions are now correctly skipped — only lockfile-resolved pins drive the verdict.
- New `is_range_constraint()` helper in `scanner/core/matcher.py` covers every operator across npm and PyPI conventions (`^`, `~`, `>=`, `>`, `<=`, `<`, `!=`, `~=`, `*`).

### Added

- 21 regression tests for range-expression detection. Full suite now 33/33 passing.

### Published

- PyPI `tridentchain-security` 0.1.3, `tridentchain-mcp` 0.1.3
- MCP Registry 0.1.3

---

## [0.1.2] — 2026-05-22

**`tridentchain-security` 0.1.2** · **`tridentchain-mcp` 0.1.2**

### Added

- Registration with the official MCP Registry at `registry.modelcontextprotocol.io` as `io.github.DevInder1/tridentchain-security`. First version to be discoverable via `uvx tridentchain-mcp` from any MCP client.
- `server.json` for the MCP Registry, with PyPI package type and stdio transport.
- `mcp-name: io.github.DevInder1/tridentchain-security` ownership marker in the `tridentchain-mcp` package README for registry ownership verification.
- Cross-client install configs for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, and Zed (`integrations/`).

### Changed

- `tridentchain-mcp` dependency on `mcp` upgraded to `mcp[cli]>=1.6.0` for `uvx` and `mcp dev` support.
- All MCP tool parameters now carry `Annotated[...]` descriptions per the MCP specification, improving tool-call quality.
- Added `--version`/`-V` flag to both the `tridentchain-security` CLI and the `tridentchain-mcp` server.

### Published

- PyPI `tridentchain-security` 0.1.2, `tridentchain-mcp` 0.1.2
- MCP Registry 0.1.2 (first registry entry)

---

## [0.1.1] — 2026-05-20

**`tridentchain-mcp` 0.1.1** (initial MCP release)

### Added

- First release of the `tridentchain-mcp` stdio MCP server, wrapping the scanner with three MCP tools:
  - `scan_project` — project-only dependency scan
  - `scan_full` — project + OS packages + IDE extensions
  - `validate_after_patch` — before/after diff for upgrade validation
- Each tool annotated with `title`, `readOnlyHint`, `destructiveHint`, and `openWorldHint` per the MCP spec.
- Published to PyPI as `tridentchain-mcp`.

---

## [0.1.0] — initial

**`tridentchain-security` 0.1.0** (scanner engine)

### Added

- Local-first supply-chain vulnerability scanner CLI (`tridentchain-security`).
- Multi-source advisory intelligence from **OSV**, **NVD**, **GHSA**, **EPSS**, **CISA KEV**, and **Sonatype OSS Index**.
- Three scan surfaces: project dependencies (npm, PyPI, Maven, Gradle, NuGet), system packages (Homebrew, apt), and installed IDE extensions (VS Code, JetBrains).
- EPSS exploit-probability and CISA KEV catalog-based remediation prioritisation — findings ranked by real-world exploit risk, not just CVSS severity.
- HTML reports: executive dashboard, per-CVE detail, EPSS-prioritised remediation queue.
- JSON report format for programmatic consumption.
- Local SQLite advisory cache for offline work and repeat-scan performance.
- `--validate` / `--baseline-report` / `--after-report` CLI flags for the before/after upgrade workflow.
- MIT license.

---

[0.1.5]: https://github.com/DevInder1/supply-chain-scanner-public/releases/tag/v0.1.5
[0.1.4]: https://github.com/DevInder1/supply-chain-scanner-public/releases/tag/v0.1.4
[0.1.3]: https://github.com/DevInder1/supply-chain-scanner-public/releases/tag/v0.1.3
[0.1.2]: https://pypi.org/project/tridentchain-mcp/0.1.2/
[0.1.1]: https://pypi.org/project/tridentchain-mcp/0.1.1/
[0.1.0]: https://pypi.org/project/tridentchain-security/0.1.0/
