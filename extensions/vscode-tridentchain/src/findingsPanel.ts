import * as vscode from "vscode";
import type { ScanSummary } from "./types";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderSummary(summary: ScanSummary, transport: string): string {
  const items =
    summary.findings ??
    (summary.affected_components ?? []).map((c) => ({
      package: c.name,
      version: c.version,
      vulnerability_count: c.vulnerabilities,
      severity: c.severity,
    }));

  const rows = items
    .slice(0, 50)
    .map(
      (f) =>
        `<tr><td>${escapeHtml(f.package ?? "")}</td><td>${escapeHtml(
          f.version ?? ""
        )}</td><td>${f.vulnerability_count ?? 0}</td><td>${escapeHtml(
          JSON.stringify(f.severity ?? {})
        )}</td></tr>`
    )
    .join("");

  const paths = summary.output_paths ?? {};
  const links = Object.entries(paths)
    .filter(([, p]) => p)
    .map(
      ([key, p]) =>
        `<li><a href="file://${escapeHtml(String(p))}">${escapeHtml(key)}: ${escapeHtml(
          String(p)
        )}</a></li>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid var(--vscode-panel-border); padding: 6px; text-align: left; }
    th { background: var(--vscode-editor-inactiveSelectionBackground); }
  </style>
</head>
<body>
  <h2>TridentChain Security</h2>
  <p>Transport: <strong>${escapeHtml(transport)}</strong> (MCP = Anthropic-aligned local <code>tridentchain-mcp</code>)</p>
  <p>Schema: ${escapeHtml(summary.schema_version ?? "n/a")} · Tool: ${escapeHtml(summary.tool ?? "cli")}</p>
  <h3>Findings (top 50)</h3>
  <table>
    <thead><tr><th>Package</th><th>Version</th><th>Vulns</th><th>Severity</th></tr></thead>
    <tbody>${rows || "<tr><td colspan='4'>No vulnerable components reported.</td></tr>"}</tbody>
  </table>
  <h3>Reports</h3>
  <ul>${links || "<li>No report paths in summary.</li>"}</ul>
</body>
</html>`;
}

let panel: vscode.WebviewPanel | undefined;

export function showFindingsPanel(
  _context: vscode.ExtensionContext,
  summary: ScanSummary,
  transport: string
): void {
  if (!panel) {
    panel = vscode.window.createWebviewPanel(
      "tridentchainFindings",
      "TridentChain Findings",
      vscode.ViewColumn.Beside,
      { enableScripts: false, retainContextWhenHidden: true }
    );
    panel.onDidDispose(() => {
      panel = undefined;
    });
  }
  panel.webview.html = renderSummary(summary, transport);
  panel.reveal();
}
