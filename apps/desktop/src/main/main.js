const path = require("path");
const { app, BrowserWindow, ipcMain, shell, dialog } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");

let activeScanChild = null;
/** Absolute dirs allowed for opening reports (last successful scan output + defaults). */
let trustedReportRoots = [];

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 860,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });

  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.loadFile(path.join(__dirname, "../renderer/index.html"));
}

function resolvePythonCommand() {
  const bundledPython = process.platform === "win32"
    ? path.join(process.resourcesPath, "runtime", "python", "python.exe")
    : path.join(process.resourcesPath, "runtime", "python", "bin", "python3");
  if (fs.existsSync(bundledPython)) {
    return bundledPython;
  }
  return process.platform === "win32" ? "python" : "python3";
}

function resolveRepoRoot() {
  if (app.isPackaged) {
    return process.resourcesPath;
  }
  return path.resolve(__dirname, "../../../..");
}

const SUPPORTED_MANIFESTS = [
  "package.json",
  "packages.lock.json",
  "packages.config",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "gradle.lockfile"
];

function hasSupportedManifest(targetDir) {
  return SUPPORTED_MANIFESTS.some((manifestName) =>
    fs.existsSync(path.join(targetDir, manifestName))
  );
}

function findProjectPath() {
  const repoRoot = resolveRepoRoot();
  if (hasSupportedManifest(repoRoot)) {
    return repoRoot;
  }

  // Prefer shallow children for startup speed.
  const children = fs.readdirSync(repoRoot, { withFileTypes: true });
  for (const child of children) {
    if (!child.isDirectory()) continue;
    if (child.name.startsWith(".") || child.name === "node_modules") continue;
    const childPath = path.join(repoRoot, child.name);
    if (hasSupportedManifest(childPath)) {
      return childPath;
    }
  }
  return repoRoot;
}

function resolveScannerCwd() {
  const bundledScannerRoot = path.join(process.resourcesPath, "runtime", "scanner");
  if (fs.existsSync(path.join(bundledScannerRoot, "scanner", "main.py"))) {
    return bundledScannerRoot;
  }
  return resolveRepoRoot();
}

function loadRepoEnv() {
  const env = { ...process.env };
  const candidates = [path.join(resolveRepoRoot(), ".env")];
  if (app.isPackaged) {
    candidates.push(path.join(path.dirname(app.getPath("exe")), ".env"));
  }
  for (const envPath of candidates) {
    if (!fs.existsSync(envPath)) continue;
    const rows = fs.readFileSync(envPath, "utf-8").split(/\r?\n/);
    for (const row of rows) {
      const line = row.trim();
      if (!line || line.startsWith("#") || !line.includes("=")) continue;
      const index = line.indexOf("=");
      const key = line.slice(0, index).trim();
      if (!key || Object.prototype.hasOwnProperty.call(process.env, key)) {
        continue;
      }
      let value = line.slice(index + 1).trim();
      if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (value !== "") env[key] = value;
    }
  }
  return env;
}

function createScannerArgs(profile) {
  const args = ["-m", "scanner.main", "--run-profile", profile.runProfile, "--scan", profile.scan];
  if (profile.projectPath) args.push("--project-path", profile.projectPath);
  if (profile.offline) args.push("--offline");
  if (profile.outputDir) args.push("--output-dir", profile.outputDir);
  return args;
}

function profileWithRules(profile) {
  const next = { ...profile };
  if (next.runProfile === "quick") next.scan = "project";
  if (next.runProfile === "full") next.scan = "all";
  if (next.runProfile === "power") {
    next.runProfile = "full";
    next.scan = "all";
  }
  return next;
}

function requiresProjectManifest(scan) {
  return scan === "project" || scan === "all";
}

function parseSummary(stdout) {
  const lines = stdout.trim().split("\n");
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (!lines[index].trim().startsWith("{")) continue;
    const candidate = lines.slice(index).join("\n");
    try {
      return JSON.parse(candidate);
    } catch (_err) {
      // Continue trying earlier JSON block candidates.
    }
  }
  return null;
}

function isPathInside(parentPath, childPath) {
  const parent = path.resolve(parentPath);
  const child = path.resolve(childPath);
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function isSafeReportPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") return false;
  if (targetPath.includes("\0")) return false;
  const normalized = path.resolve(targetPath);
  const ext = path.extname(normalized).toLowerCase();
  if (![".json", ".html", ".htm"].includes(ext)) return false;

  const repoRoot = resolveRepoRoot();
  const scannerRoot = path.join(repoRoot, "scanner");
  const allowedRoots = [
    scannerRoot,
    path.join(scannerRoot, "desktop-output"),
    path.join(scannerRoot, "desktop-output-compare"),
    ...trustedReportRoots
  ];
  return allowedRoots.some((root) => isPathInside(path.resolve(root), normalized));
}

ipcMain.handle("scanner:buildCommand", async (_, profile) => {
  const python = resolvePythonCommand();
  const args = createScannerArgs(profileWithRules(profile));
  return `${python} ${args.map((part) => (part.includes(" ") ? `"${part}"` : part)).join(" ")}`;
});

ipcMain.handle("scanner:detectProjectPath", async () => {
  return findProjectPath();
});

ipcMain.handle("scanner:run", async (_, profile) => {
  const normalizedProfile = profileWithRules(profile);
  const python = resolvePythonCommand();
  const args = createScannerArgs(normalizedProfile);
  const cwd = resolveScannerCwd();
  const env = loadRepoEnv();

  if (requiresProjectManifest(normalizedProfile.scan)) {
    const selectedPath = normalizedProfile.projectPath || "";
    if (!selectedPath) {
      return {
        code: 2,
        stdout: "",
        stderr: "Project path is required for project/all scans. Use Browse to pick a folder.",
        summary: null
      };
    }
    if (!fs.existsSync(selectedPath) || !fs.statSync(selectedPath).isDirectory()) {
      return {
        code: 2,
        stdout: "",
        stderr: "Selected project path does not exist or is not a directory.",
        summary: null
      };
    }
  }

  return new Promise((resolve) => {
    if (activeScanChild) {
      resolve({
        code: 3,
        stdout: "",
        stderr: "A scan is already running. Stop it before starting another one.",
        summary: null
      });
      return;
    }
    trustedReportRoots = [];
    if (normalizedProfile.outputDir && String(normalizedProfile.outputDir).trim()) {
      try {
        trustedReportRoots.push(path.resolve(String(normalizedProfile.outputDir).trim()));
      } catch (_e) {
        // Ignore invalid outputDir; default scanner roots still apply.
      }
    }

    const child = spawn(python, args, { cwd, env, shell: false });
    activeScanChild = child;
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      BrowserWindow.getAllWindows()[0]?.webContents.send("scanner:log", text);
    });

    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      BrowserWindow.getAllWindows()[0]?.webContents.send("scanner:log", text);
    });

    child.on("close", (code) => {
      activeScanChild = null;
      const summary = parseSummary(stdout);
      resolve({ code, stdout, stderr, summary });
    });
  });
});

ipcMain.handle("scanner:stop", async () => {
  if (!activeScanChild) {
    return { stopped: false, reason: "No active scan process" };
  }
  const pid = activeScanChild.pid;
  try {
    activeScanChild.kill("SIGTERM");
  } catch (_err) {
    // Ignore and report stopped=false below if still running.
  }
  return { stopped: true, pid };
});

ipcMain.handle("scanner:browseProjectPath", async () => {
  const win = BrowserWindow.getAllWindows()[0];
  const result = await dialog.showOpenDialog(win, {
    title: "Select project folder",
    properties: ["openDirectory", "createDirectory"]
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

ipcMain.handle("scanner:openPath", async (_, targetPath) => {
  if (!targetPath) return false;
  if (!isSafeReportPath(targetPath)) return false;
  if (!fs.existsSync(targetPath)) return false;
  const opened = await shell.openPath(targetPath);
  if (!opened) {
    return true;
  }
  await shell.showItemInFolder(targetPath);
  return false;
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
