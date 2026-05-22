# Plugin submission pack — TridentChain Security

Pre-filled text for Anthropic **plugin** and **local connector** review forms.

---

## Server / plugin basics

| Field | Value |
|-------|--------|
| **Name** | TridentChain Security |
| **Slug / ID** | `tridentchain-security` |
| **Tagline** | Local supply-chain vulnerability scanning for your repo |
| **Category** | Security / Developer tools |
| **Version** | 0.1.2 (aligned with PyPI `tridentchain-security`) |

### Description (short)

TridentChain Security scans project dependencies, system packages, and IDE extensions for known vulnerabilities using OSV, NVD, and related sources. Runs locally via MCP — no hosted upload of your source code. Includes validate-after-patch workflow for dependency upgrades.

### Use cases

- Scan `package.json` / lockfiles / Python deps before release
- Find CVEs and EPSS-prioritized remediation in a local report
- Re-scan after `npm update` / `pip install -U` and diff results
- Supply-chain review in Claude Code without leaving the IDE

---

## Connection details

| Field | Value |
|-------|--------|
| **Type** | Local stdio MCP |
| **Transport** | stdio |
| **Command** | `python3 -m tridentchain_mcp` (or `tridentchain-mcp` on PATH) |
| **Auth** | None (local); optional user env keys for NVD/GitHub rate limits |
| **OAuth** | Not applicable |
| **Read/write** | Reads project files; writes scan reports to user-specified `output_dir` |

### Prerequisites for reviewers

```bash
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"
# → tridentchain-security
```

Test repo: any open-source Node or Python project with `package.json` or `requirements.txt`.

### Reviewer test steps

1. Install packages above.
2. Claude Code: `claude --plugin-dir ./plugins/tridentchain-security`
3. Invoke skill `/tridentchain-security:supply-chain-scan` or MCP tool `scan_project` with `project_path` = test repo root, `output_dir` = `.tridentchain-out`.
4. Confirm `.tridentchain-out/scan-report.json` exists.
5. Optional: run `validate_after_patch` with two scan JSON blobs.

---

## Tools (with annotations)

| Tool | Human title | readOnlyHint | destructiveHint | Description |
|------|-------------|--------------|-----------------|-------------|
| `scan_project` | Scan Project Dependencies | false | false | Project deps only |
| `scan_full` | Scan Workspace (Full) | false | false | Project + OS + IDE extensions |
| `validate_after_patch` | Validate After Patch | true | false | Diff two scan summaries |

---

## Data & compliance

| Topic | Answer |
|-------|--------|
| **Data leaves device?** | Only package/version queries to public advisory APIs; source code stays local |
| **Health data** | No |
| **Third-party** | OSV, NVD, optional GHSA/Sonatype with user tokens |
| **Privacy policy** | https://raw.githubusercontent.com/DevInder1/supply-chain-scanner-public/main/plugins/tridentchain-security/PRIVACY.md |

---

## Documentation & support

| Link | URL |
|------|-----|
| Repository | https://github.com/DevInder1/supply-chain-scanner-public |
| Install guide | https://github.com/DevInder1/supply-chain-scanner-public/blob/main/docs/CLAUDE_MCP_SETUP.md |
| Agent matrix | https://github.com/DevInder1/supply-chain-scanner-public/blob/main/docs/AGENT_INTEGRATIONS.md |
| Privacy | https://raw.githubusercontent.com/DevInder1/supply-chain-scanner-public/main/plugins/tridentchain-security/PRIVACY.md |
| Issues | https://github.com/DevInder1/supply-chain-scanner-public/issues |

---

## Launch readiness

| Surface | Status |
|---------|--------|
| Claude Code — `claude mcp add` (global) | ✓ Connected (verified 2026-05-22) |
| Claude Code — plugin `--plugin-dir` | ✓ Skills load, `claude plugin validate` passes |
| Claude Code — project `.mcp.json` | ✓ Auto-discovered |
| Claude Desktop — `mcpServers` | ✓ Config documented, stdio handshake verified |
| Cursor — `.cursor/mcp.json` | ✓ Config documented |
| VS Code — `.vscode/mcp.json` (`type: stdio`) | ✓ Config documented |
| Windsurf — `mcp_config.json` | ✓ Config documented |
| Zed — `context_servers` | ✓ Config documented |

**GA:** Both PyPI packages published and live — `tridentchain-security@0.1.2`, `tridentchain-mcp@0.1.1`. All three MCP tools carry `title`, `readOnlyHint`, `destructiveHint`, `openWorldHint`, and `Annotated` parameter descriptions per spec.

---

## Allowed link URIs

Optional — TridentChain does not use `ui/open-link` by default. If enabled later, declare only owned domains:

- `https://github.com/DevInder1/supply-chain-scanner-public`

---

## Branding

- **Logo:** `.claude-plugin/icon.svg` in plugin folder (submit SVG or host on GitHub raw)
- **Logo URL (raw SVG):** https://raw.githubusercontent.com/DevInder1/supply-chain-scanner-public/main/plugins/tridentchain-security/.claude-plugin/icon.svg

---

## Related submission types

| Type | Form | TridentChain fit |
|------|------|------------------|
| Plugin + skills | Plugin marketplace | **Primary — ready** |
| Desktop MCPB | Desktop extension form | Phase 6 optional |
| Remote MCP directory | MCP directory form | Requires hosted server (not built) |

---

## Validate before submit

```bash
./scripts/validate-plugin.sh
claude plugin validate ./plugins/tridentchain-security   # if available
```

Checklist: [plugins/tridentchain-security/SUBMISSION_CHECKLIST.md](../plugins/tridentchain-security/SUBMISSION_CHECKLIST.md)
