import { spawn } from "child_process";
import * as path from "path";
import * as vscode from "vscode";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ScanMode, ScanSummary } from "./types";

export interface ScanRequest {
  workspaceRoot: string;
  outputDir: string;
  mode: ScanMode;
  runProfile: string;
}

export interface ScanResult {
  summary: ScanSummary;
  transport: "mcp" | "cli";
}

function getConfig() {
  return vscode.workspace.getConfiguration("tridentchain");
}

function parseToolJson(text: string): ScanSummary {
  const parsed = JSON.parse(text) as ScanSummary;
  if (parsed.raw_summary && typeof parsed.raw_summary === "object") {
    return parsed;
  }
  return parsed;
}

function parseCliStdout(stdout: string): ScanSummary {
  const lines = stdout.split("\n").filter((ln) => ln.trim().startsWith("{"));
  if (!lines.length) {
    throw new Error("CLI produced no JSON summary on stdout.");
  }
  return JSON.parse(lines[lines.length - 1]) as ScanSummary;
}

async function scanViaMcp(request: ScanRequest): Promise<ScanSummary> {
  const mcpCommand = getConfig().get<string>("mcp.command", "tridentchain-mcp");
  const transport = new StdioClientTransport({
    command: mcpCommand,
    args: [],
  });
  const client = new Client(
    { name: "vscode-tridentchain", version: "0.1.0" },
    { capabilities: {} }
  );
  await client.connect(transport);
  try {
    const result = await client.callTool({
      name: request.mode,
      arguments: {
        project_path: request.workspaceRoot,
        output_dir: request.outputDir,
        run_profile: request.runProfile,
        max_findings: 50,
      },
    });
    const blocks = Array.isArray(result.content) ? result.content : [];
    const textBlock = blocks.find(
      (b: { type?: string; text?: string }): b is { type: "text"; text: string } =>
        b?.type === "text" && typeof b.text === "string"
    );
    const text =
      textBlock && "text" in textBlock
        ? String(textBlock.text)
        : JSON.stringify(result);
    return parseToolJson(text);
  } finally {
    await client.close();
  }
}

function scanViaCli(request: ScanRequest): Promise<ScanSummary> {
  const cliCommand = getConfig().get<string>("cli.command", "tridentchain-security");
  const scanFlag = request.mode === "scan_project" ? "project" : "all";
  return new Promise((resolve, reject) => {
    const child = spawn(
      cliCommand,
      [
        "--scan",
        scanFlag,
        "--project-path",
        request.workspaceRoot,
        "--output-dir",
        request.outputDir,
        "--run-profile",
        request.runProfile,
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (err) => reject(err));
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `CLI exited with code ${code}`));
        return;
      }
      try {
        resolve(parseCliStdout(stdout));
      } catch (err) {
        reject(err);
      }
    });
  });
}

export async function runScan(
  folder: vscode.WorkspaceFolder,
  mode: ScanMode
): Promise<ScanResult> {
  const cfg = getConfig();
  const outputRel = cfg.get<string>("outputDir", ".tridentchain-out");
  const outputDir = path.join(folder.uri.fsPath, outputRel);
  const request: ScanRequest = {
    workspaceRoot: folder.uri.fsPath,
    outputDir,
    mode,
    runProfile: cfg.get<string>("runProfile", "full"),
  };

  const preferMcp = cfg.get<boolean>("preferMcp", true);
  if (preferMcp) {
    try {
      const summary = await scanViaMcp(request);
      return { summary, transport: "mcp" };
    } catch (mcpErr) {
      const msg = mcpErr instanceof Error ? mcpErr.message : String(mcpErr);
      vscode.window.showWarningMessage(
        `TridentChain MCP unavailable (${msg}). Falling back to CLI.`
      );
    }
  }

  const summary = await scanViaCli(request);
  return { summary, transport: "cli" };
}

export async function validateAfterPatch(
  baseline: ScanSummary,
  afterPatch: ScanSummary
): Promise<Record<string, unknown>> {
  const cfg = getConfig();
  if (cfg.get<boolean>("preferMcp", true)) {
    try {
      const mcpCommand = cfg.get<string>("mcp.command", "tridentchain-mcp");
      const transport = new StdioClientTransport({ command: mcpCommand, args: [] });
      const client = new Client(
        { name: "vscode-tridentchain", version: "0.1.0" },
        { capabilities: {} }
      );
      await client.connect(transport);
      try {
        const result = await client.callTool({
          name: "validate_after_patch",
          arguments: {
            baseline_json: JSON.stringify(baseline),
            after_patch_json: JSON.stringify(afterPatch),
          },
        });
        const blocks = Array.isArray(result.content) ? result.content : [];
        const textBlock = blocks.find(
          (b: { type?: string; text?: string }): b is { type: "text"; text: string } =>
            b?.type === "text" && typeof b.text === "string"
        );
        const text =
          textBlock && "text" in textBlock
            ? String(textBlock.text)
            : JSON.stringify(result);
        return JSON.parse(text) as Record<string, unknown>;
      } finally {
        await client.close();
      }
    } catch {
      /* fall through to local diff */
    }
  }

  const baseRaw = baseline.raw_summary ?? baseline;
  const afterRaw = afterPatch.raw_summary ?? afterPatch;
  const keys = (raw: ScanSummary) =>
    new Set(
      (raw.affected_components ?? []).map((c) => `${c.name}@${c.version}`)
    );
  const before = keys(baseRaw);
  const after = keys(afterRaw);
  const resolved = [...before].filter((k) => !after.has(k));
  const remaining = [...before].filter((k) => after.has(k));
  const newOnes = [...after].filter((k) => !before.has(k));
  return {
    status: "ok",
    resolved_count: resolved.length,
    remaining_count: remaining.length,
    new_count: newOnes.length,
    validation_passed: newOnes.length === 0 && resolved.length > 0,
  };
}
