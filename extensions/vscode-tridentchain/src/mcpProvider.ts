import * as vscode from "vscode";

const PROVIDER_ID = "tridentchainProvider";

function getMcpCommand(): { command: string; args: string[] } {
  const cfg = vscode.workspace.getConfiguration("tridentchain");
  const custom = cfg.get<string>("mcp.command", "tridentchain-mcp");
  if (custom && custom !== "tridentchain-mcp") {
    return { command: custom, args: [] };
  }
  return { command: "python3", args: ["-m", "tridentchain_mcp"] };
}

/** Register TridentChain MCP so it appears in VS Code without manual mcp.json editing. */
export function registerMcpProvider(context: vscode.ExtensionContext): void {
  if (typeof vscode.lm.registerMcpServerDefinitionProvider !== "function") {
    return;
  }

  const emitter = new vscode.EventEmitter<void>();
  const { command, args } = getMcpCommand();

  context.subscriptions.push(
    vscode.lm.registerMcpServerDefinitionProvider(PROVIDER_ID, {
      onDidChangeMcpServerDefinitions: emitter.event,
      provideMcpServerDefinitions: async () => {
        const McpStdio = vscode.McpStdioServerDefinition;
        if (!McpStdio) {
          return [];
        }
        return [new McpStdio("TridentChain Security", command, args)];
      },
      resolveMcpServerDefinition: async (definition: { label?: string }) => {
        if (definition.label === "TridentChain Security") {
          const choice = await vscode.window.showInformationMessage(
            "TridentChain MCP uses local Python packages. Install with: pip install tridentchain-security tridentchain-mcp",
            "Copy install command"
          );
          if (choice === "Copy install command") {
            await vscode.env.clipboard.writeText(
              "pip install \"tridentchain-security>=0.1.2\" tridentchain-mcp"
            );
          }
        }
        return definition;
      },
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("tridentchain.mcp.command")) {
        emitter.fire();
      }
    })
  );
}
