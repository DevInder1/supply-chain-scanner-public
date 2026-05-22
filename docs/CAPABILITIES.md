# TridentChain Security — What You Can Do Today

This guide lists everything available with the **current published stack**:

| Package | Install | Role |
|---------|---------|------|
| **tridentchain-security** | `pip install tridentchain-security` | Core scanner + CLI (universal fallback) |
| **tridentchain-security ≥0.1.1** | `pip install "tridentchain-security>=0.1.1"` | Unified tool layer (`scanner.integrations`) |
| **tridentchain-mcp** | `pip install tridentchain-mcp` | Local stdio MCP server (Claude, Cursor, VS Code, agents) |
| **@tridentchain/security-cli** | `npm install -g @tridentchain/security-cli` | npm wrapper → same Python CLI |

**Older installs keep working:** `pip install tridentchain-security==0.1.0` still runs scans; only ≥0.1.1 adds integrations + validate CLI.

---

## Recommended install (agents + IDE)

```bash
pip3 install "tridentchain-security>=0.1.1"
pip3 install tridentchain-mcp
```

Verify:

```bash
tridentchain-security --help
python3 -c "from scanner.integrations import get_tool_definitions; print(len(get_tool_definitions()), 'tools')"
python3 -c "from tridentchain_mcp.server import mcp; print('MCP:', mcp.name)"
```

---

## 1. Command-line (`tridentchain-security`)

### Scan commands (all versions ≥0.1.0)

| Command | Description |
|---------|-------------|
| `--scan project` | Project dependencies only |
| `--scan all` | Project + system packages + IDE extensions |
| `--scan system` | System packages |
| `--run-profile quick\|full\|offline` | Speed vs coverage |
| `--project-path <dir>` | Workspace / repo root |
| `--output-dir <dir>` | Writes `scan-report.json`, HTML reports |

**Example:**

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

Stdout ends with a **JSON summary** (`affected_components`, `output_paths`, etc.).

### Validate after patch (≥0.1.1, Phase 5)

Compare two existing reports without re-scanning:

```bash
# 1) Baseline scan
tridentchain-security --scan project --project-path . --output-dir .tridentchain-out

# 2) Upgrade dependencies, then scan again (same output dir or copy reports)

# 3) Validate
tridentchain-security --validate \
  --baseline-report .tridentchain-out/scan-report.json \
  --after-report .tridentchain-out/scan-report.json
```

Use two different files if you saved baseline before overwriting, e.g. `baseline.json` and `scan-report.json`.

**Validate output fields:** `resolved_count`, `remaining_count`, `new_count`, `validation_passed`, `resolved`, `new_findings`.

---

## 2. Python API

```python
from scanner import run_scan
from scanner.integrations import execute_tool, get_tool_definitions, validate_after_patch

# Direct scan
summary = run_scan(project_path=".", scan="project", output_dir=".tridentchain-out")

# Unified tools (same as MCP)
result = execute_tool("scan_project", {"project_path": ".", "output_dir": ".tridentchain-out"})
diff = validate_after_patch(baseline_summary, after_summary)
```

---

## 3. MCP server (`tridentchain-mcp`)

Stdio MCP host — **Anthropic-aligned local server** (no cloud connector).

| Tool | Purpose |
|------|---------|
| `scan_project` | Fast project dependency scan |
| `scan_full` | Full coverage |
| `validate_after_patch` | Diff baseline vs after-patch JSON strings |

**Hosts:** Claude Desktop, Claude Code (plugin), Cursor, VS Code extension, any MCP client.

**Config** (same everywhere):

```json
{
  "servers": {
    "tridentchain": {
      "type": "stdio",
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

(Claude Desktop / Cursor: use `"mcpServers"` instead of `"servers"` — same command.)

**VS Code (native MCP):** copy `integrations/vscode/mcp.json.example` → `.vscode/mcp.json` (uses `"servers"` per [VS Code MCP reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration)).

**Claude / Cursor** use `"mcpServers"` in their config files — same `command: tridentchain-mcp`.

Examples: [VSCODE_SETUP.md](VSCODE_SETUP.md), [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md), [CURSOR_SETUP.md](CURSOR_SETUP.md).

---

## 4. Platform integrations

| Platform | How | Doc |
|----------|-----|-----|
| **Shell / CI** | `tridentchain-security` CLI | [INSTALL_AND_USE.md](INSTALL_AND_USE.md) |
| **Claude** | MCP + [plugin](../plugins/tridentchain-security/) | [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md) |
| **Cursor** | MCP + project rule | [CURSOR_SETUP.md](CURSOR_SETUP.md) |
| **VS Code** | Extension (MCP-first) | [VSCODE_SETUP.md](VSCODE_SETUP.md) |
| **OpenAI** | `to_openai_tools()` + examples | [examples/openai/](../examples/openai/) |
| **npm** | `@tridentchain/security-cli` | [INSTALL_AND_USE.md](INSTALL_AND_USE.md) |
| **Desktop UI** | Electron app (repo) | `apps/desktop/` |

---

## 5. Daybreak-style workflow (detect → patch → validate)

```text
baseline  = scan_full(project)     # MCP scan_full or CLI --scan all
# upgrade packages
after     = scan_full(project)
diff      = validate_after_patch(baseline, after)
```

| Step | MCP | CLI |
|------|-----|-----|
| Baseline | `scan_project` / `scan_full` | `tridentchain-security --scan …` |
| Re-scan | same | same |
| Validate | `validate_after_patch` | `--validate --baseline-report … --after-report …` |

Claude skill: [validate-fixes](../plugins/tridentchain-security/skills/validate-fixes/SKILL.md).

---

## 6. Reports for humans and agents

| File | Use |
|------|-----|
| `scan-report.json` | Structured data |
| `scan-report.html` | Summary |
| `scan-vulnerabilities.html` | Vuln + fixes |
| `scan-remediation-epss.html` | EPSS prioritization |

---

## 7. Version matrix

| Version | Scan CLI | `scanner.integrations` | `--validate` CLI |
|---------|----------|------------------------|------------------|
| 0.1.0 | ✅ | ❌ | ❌ |
| ≥0.1.1 | ✅ | ✅ | ✅ |
| 0.1.2 (latest repo) | ✅ | ✅ | ✅ `--validate` CLI |

Pin when needed:

```bash
pip install tridentchain-security==0.1.0   # legacy, scan only
pip install "tridentchain-security>=0.1.1" # agents + validate
```

`tridentchain-mcp` requires `tridentchain-security>=0.1.1`.

---

## 8. Security defaults

- No API keys required for default `full` profile (OSV-first).
- Optional: `NVD_API_KEY`, `GITHUB_TOKEN` via environment.
- MCP and tools stay **local** — no hosted scan API.

---

## Related

- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md)
- [ROADMAP_INTEGRATIONS.md](ROADMAP_INTEGRATIONS.md)
- [cli-contract.md](cli-contract.md)
