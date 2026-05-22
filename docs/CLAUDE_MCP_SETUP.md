# Use TridentChain with Claude (MCP) — Step by Step

Everything below uses **published PyPI packages** (no repo clone required for MCP).

| Package | PyPI | Version |
|---------|------|---------|
| `tridentchain-security` | https://pypi.org/project/tridentchain-security/ | **0.1.2** (latest) |
| `tridentchain-mcp` | https://pypi.org/project/tridentchain-mcp/ | **0.1.1** (latest) |

npm `@tridentchain/security-cli` is optional (CLI wrapper only).

---

## Step 1 — Install (terminal)

### Option A — uvx (zero persistent install, Anthropic-recommended)

`uvx` runs `tridentchain-mcp` in an isolated environment automatically — no `pip install` needed:

```bash
# Install uv once (if not already present)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Verify the MCP server works
uvx tridentchain-mcp --version
```

Skip to Step 2 and use `"command": "uvx"` in the config.

### Option B — pip install (classic)

```bash
pip3 install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
```

Use `python3 -m pip` if `pip3` fails on macOS.

**Verify:**

```bash
tridentchain-security --version
tridentchain-mcp --version
python3 -c "from tridentchain_mcp.server import mcp; print('MCP server:', mcp.name)"
```

Expected MCP name: `tridentchain-security`.

---

## Step 2 — Choose your Claude app

### A) Claude Desktop (chat app)

1. Quit Claude Desktop completely.
2. Open the MCP config file:
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
3. Add or merge this block (keep other servers if you have them):

**uvx (recommended — Anthropic official pattern, no pip install):**

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "uvx",
      "args": ["tridentchain-mcp"]
    }
  }
}
```

**pip-installed fallback:**

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

**Most portable form (works even if the script isn't on PATH):**

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "python3",
      "args": ["-m", "tridentchain_mcp"]
    }
  }
}
```

4. Save the file and **restart Claude Desktop**.
5. In a new chat, enable MCP tools (hammer/tools icon) and confirm **tridentchain** appears.
6. Try:

> Scan this folder for supply-chain vulnerabilities. Use scan_project with project_path set to my workspace and output_dir `.tridentchain-out`.

---

### B) Claude Code (terminal IDE)

**Option 1 — `claude mcp add` (one-liner, persists globally)**

```bash
# uvx variant (recommended — no pip install needed)
claude mcp add tridentchain -- uvx tridentchain-mcp

# pip variant
claude mcp add tridentchain -- python3 -m tridentchain_mcp
```

**Option 2 — Project-level `.mcp.json` (auto-discovered when you `cd` into the project)**

1. In your project root, create `.mcp.json`:

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "uvx",
      "args": ["tridentchain-mcp"]
    }
  }
}
```

2. Start Claude Code in that folder: `claude`
3. Ask Claude to run `scan_project` or `scan_full`.

**Option 3 — Official plugin (skills + MCP)**

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
pip3 install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
claude --plugin-dir ./plugins/tridentchain-security
```

Skills:

- `/tridentchain-security:supply-chain-scan`
- `/tridentchain-security:validate-fixes`

---

## Step 3 — MCP tools you can use

| Tool | When to use |
|------|-------------|
| `scan_project` | Fast — project dependencies only |
| `scan_full` | Full — project + OS packages + IDE extensions |
| `validate_after_patch` | After upgrading deps — compare two scan JSON results |

Reports are written under `.tridentchain-out/` (or the `output_dir` you pass).

---

## Step 4 — Example prompts in Claude

**Scan:**

> Use the tridentchain MCP tool scan_project on this workspace. project_path is the repo root, output_dir is `.tridentchain-out`. Summarize findings by severity.

**Full scan:**

> Run scan_full on this project with output_dir `.tridentchain-out`.

**After upgrading packages:**

> Run scan_project twice (before/after) or use validate_after_patch with baseline and after-patch JSON from the scans.

---

## Step 5 — CLI fallback (if MCP does not connect)

```bash
cd /path/to/your/project
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

Then ask Claude to read `.tridentchain-out/scan-report.json`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| MCP server not listed | Restart Claude; check JSON syntax; run `which tridentchain-mcp` |
| `command not found` | Use `python3 -m tridentchain_mcp` in config instead |
| Tools grayed out | Install packages again; check Claude MCP/tools settings |
| Slow first scan | First run downloads advisory data; later runs use cache |
| Old behavior | Pin `tridentchain-security==0.1.0` (no MCP); for MCP use **≥0.1.1** |

---

## Related

- [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md) — all agents
- [CAPABILITIES.md](CAPABILITIES.md) — full feature list
- [PLUGIN_SUBMISSION.md](PLUGIN_SUBMISSION.md) — Anthropic submission pack
