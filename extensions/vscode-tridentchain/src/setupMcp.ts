import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

const MCP_TEMPLATE = {
  servers: {
    tridentchain: {
      type: "stdio",
      command: "python3",
      args: ["-m", "tridentchain_mcp"],
    },
  },
};

export async function setupWorkspaceMcp(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showErrorMessage("Open a folder first, then run Setup MCP.");
    return;
  }

  const vscodeDir = path.join(folder.uri.fsPath, ".vscode");
  const mcpPath = path.join(vscodeDir, "mcp.json");

  if (fs.existsSync(mcpPath)) {
    const overwrite = await vscode.window.showWarningMessage(
      ".vscode/mcp.json already exists. Overwrite with TridentChain config?",
      "Overwrite",
      "Cancel"
    );
    if (overwrite !== "Overwrite") {
      const doc = await vscode.workspace.openTextDocument(mcpPath);
      await vscode.window.showTextDocument(doc);
      return;
    }
  }

  fs.mkdirSync(vscodeDir, { recursive: true });
  fs.writeFileSync(mcpPath, `${JSON.stringify(MCP_TEMPLATE, null, 2)}\n`, "utf-8");

  const doc = await vscode.workspace.openTextDocument(mcpPath);
  await vscode.window.showTextDocument(doc);
  vscode.window.showInformationMessage(
    "TridentChain MCP added. Command Palette → MCP: List Servers → start tridentchain."
  );
}

export function buildMcpInstallUri(): string {
  const payload = {
    name: "tridentchain",
    type: "stdio",
    command: "python3",
    args: ["-m", "tridentchain_mcp"],
  };
  return `vscode:mcp/install?${encodeURIComponent(JSON.stringify(payload))}`;
}

export async function openMcpInstallLink(): Promise<void> {
  const uri = vscode.Uri.parse(buildMcpInstallUri());
  const opened = await vscode.env.openExternal(uri);
  if (!opened) {
    await vscode.env.clipboard.writeText(buildMcpInstallUri());
    vscode.window.showInformationMessage(
      "Install link copied to clipboard. Paste in a browser or Run → Open Link."
    );
  }
}
