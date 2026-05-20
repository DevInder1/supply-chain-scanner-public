import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { publishDiagnostics } from "./diagnostics";
import { showFindingsPanel } from "./findingsPanel";
import { runScan, validateAfterPatch } from "./scanService";
import type { ScanSummary } from "./types";

const BASELINE_KEY = "tridentchain.baselineScan";
const LAST_SCAN_KEY = "tridentchain.lastScan";

let diagnosticCollection: vscode.DiagnosticCollection;

async function getWorkspaceFolder(): Promise<vscode.WorkspaceFolder | undefined> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    vscode.window.showErrorMessage("Open a workspace folder to run TridentChain scans.");
    return undefined;
  }
  if (folders.length === 1) {
    return folders[0];
  }
  return vscode.window.showWorkspaceFolderPick();
}

async function executeScan(
  context: vscode.ExtensionContext,
  mode: "scan_full" | "scan_project"
): Promise<void> {
  const folder = await getWorkspaceFolder();
  if (!folder) {
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "TridentChain Security",
      cancellable: false,
    },
    async (progress) => {
      progress.report({
        message:
          mode === "scan_project"
            ? "Scanning project dependencies…"
            : "Running full scan (project + system + IDE)…",
      });
      const result = await runScan(folder, mode);
      await publishDiagnostics(diagnosticCollection, folder, result.summary);
      showFindingsPanel(context, result.summary, result.transport);
      await context.workspaceState.update(LAST_SCAN_KEY, result.summary);

      const transportLabel =
        result.transport === "mcp"
          ? "MCP (tridentchain-mcp)"
          : "CLI (tridentchain-security)";
      const count =
        result.summary.findings?.length ??
        result.summary.affected_components?.length ??
        0;
      vscode.window.showInformationMessage(
        `TridentChain scan complete via ${transportLabel}. ${count} component(s) in summary.`
      );
    }
  );
}

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("tridentchain");
  context.subscriptions.push(diagnosticCollection);

  context.subscriptions.push(
    vscode.commands.registerCommand("tridentchain.scanWorkspace", () =>
      executeScan(context, "scan_full")
    ),
    vscode.commands.registerCommand("tridentchain.scanProject", () =>
      executeScan(context, "scan_project")
    ),
    vscode.commands.registerCommand("tridentchain.showReport", async () => {
      const folder = await getWorkspaceFolder();
      if (!folder) {
        return;
      }
      const outputRel = vscode.workspace
        .getConfiguration("tridentchain")
        .get<string>("outputDir", ".tridentchain-out");
      const reportPath = path.join(folder.uri.fsPath, outputRel, "scan-report.json");
      if (!fs.existsSync(reportPath)) {
        vscode.window.showWarningMessage(
          `No report at ${reportPath}. Run a scan first.`
        );
        return;
      }
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(reportPath));
      await vscode.window.showTextDocument(doc);
    }),
    vscode.commands.registerCommand("tridentchain.validateFixes", async () => {
      const folder = await getWorkspaceFolder();
      if (!folder) {
        return;
      }
      const baseline = context.workspaceState.get<ScanSummary>(BASELINE_KEY);
      if (!baseline) {
        const save = await vscode.window.showInformationMessage(
          "Save current scan as baseline, then patch dependencies and run Validate again.",
          "Scan and save baseline"
        );
        if (save) {
          const result = await runScan(folder, "scan_full");
          await context.workspaceState.update(BASELINE_KEY, result.summary);
          vscode.window.showInformationMessage("Baseline saved for validate-after-patch.");
        }
        return;
      }

      const after = await runScan(folder, "scan_full");
      const diff = await validateAfterPatch(baseline, after.summary);
      const msg = `Resolved: ${diff.resolved_count}, remaining: ${diff.remaining_count}, new: ${diff.new_count}`;
      if (diff.validation_passed) {
        vscode.window.showInformationMessage(`TridentChain validation passed. ${msg}`);
      } else {
        vscode.window.showWarningMessage(`TridentChain validation incomplete. ${msg}`);
      }
      await context.workspaceState.update(LAST_SCAN_KEY, after.summary);
    })
  );
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}
