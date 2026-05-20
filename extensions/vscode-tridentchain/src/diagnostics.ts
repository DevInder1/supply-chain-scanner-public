import * as vscode from "vscode";
import type { ScanSummary } from "./types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

function worstSeverity(severity: Record<string, number> | undefined): vscode.DiagnosticSeverity {
  if (!severity) {
    return vscode.DiagnosticSeverity.Warning;
  }
  for (const level of SEVERITY_ORDER) {
    if ((severity[level] ?? 0) > 0) {
      switch (level) {
        case "critical":
        case "high":
          return vscode.DiagnosticSeverity.Error;
        case "medium":
          return vscode.DiagnosticSeverity.Warning;
        default:
          return vscode.DiagnosticSeverity.Information;
      }
    }
  }
  return vscode.DiagnosticSeverity.Warning;
}

function affectedList(summary: ScanSummary) {
  if (summary.findings?.length) {
    return summary.findings.map((f) => ({
      name: f.package ?? "",
      version: f.version ?? "",
      vulnerabilities: f.vulnerability_count ?? 0,
      severity: f.severity,
    }));
  }
  return summary.affected_components ?? [];
}

async function resolveTargetUri(folder: vscode.WorkspaceFolder): Promise<vscode.Uri | undefined> {
  const patterns = ["package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"];
  for (const pattern of patterns) {
    const matches = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, pattern),
      "**/node_modules/**",
      1
    );
    if (matches.length) {
      return matches[0];
    }
  }
  return undefined;
}

export async function publishDiagnostics(
  collection: vscode.DiagnosticCollection,
  folder: vscode.WorkspaceFolder,
  summary: ScanSummary
): Promise<void> {
  collection.clear();
  const target = await resolveTargetUri(folder);
  if (!target) {
    return;
  }

  const items = affectedList(summary).filter((c) => (c.vulnerabilities ?? 0) > 0);
  const diagnostics: vscode.Diagnostic[] = items.map((comp) => {
    const count = comp.vulnerabilities ?? 0;
    const sev = worstSeverity(comp.severity as Record<string, number> | undefined);
    const line = 0;
    const diag = new vscode.Diagnostic(
      new vscode.Range(line, 0, line, 1),
      `${comp.name}@${comp.version}: ${count} known vulnerabilit${count === 1 ? "y" : "ies"}`,
      sev
    );
    diag.source = "TridentChain Security";
    diag.code = "supply-chain";
    return diag;
  });

  collection.set(target, diagnostics);
}
