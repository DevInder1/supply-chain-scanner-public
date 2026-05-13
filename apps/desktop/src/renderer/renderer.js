function readProfile() {
  const runProfile = document.getElementById("runProfile").value;
  const scan = document.getElementById("scan").value;
  return {
    runProfile,
    scan,
    projectPath: document.getElementById("projectPath").value,
    outputDir: document.getElementById("outputDir").value,
    offline: runProfile === "offline"
  };
}

function setText(id, text) {
  document.getElementById(id).textContent = text;
}

function updateModeGuide() {
  const runProfile = document.getElementById("runProfile").value;
  if (runProfile === "full") {
    setText(
      "modeGuide",
      [
        "Recommended public setup",
        "- Default mode: no key required",
        "- Uses OSV + NVD by default (NVD may be rate-limited without API key)",
        "- GHSA/Sonatype are skipped automatically when tokens are missing",
        "- Power users can add GITHUB_TOKEN / NVD_API_KEY / SONATYPE_TOKEN for better coverage"
      ].join("\n")
    );
    return;
  }
  if (runProfile === "quick") {
    setText(
      "modeGuide",
      [
        "Quick setup",
        "- Faster local run, focused on project dependency findings",
        "- No API key required",
        "- Good for routine developer checks before commits"
      ].join("\n")
    );
    return;
  }
  if (runProfile === "power") {
    setText(
      "modeGuide",
      [
        "Power-user setup",
        "- Best coverage and throughput with API keys",
        "- Strongly recommended keys: GITHUB_TOKEN and NVD_API_KEY",
        "- Optional SONATYPE_TOKEN adds extra intelligence source coverage",
        "- Uses full scan mode (project + system + extensions)"
      ].join("\n")
    );
    return;
  }
  setText(
    "modeGuide",
    [
      "Offline setup",
      "- Fully local mode with no external API calls",
      "- Uses local advisory DB/cache only",
      "- Best for restricted or air-gapped environments"
    ].join("\n")
  );
}

function formatCoverageSummary(summary) {
  const byType = summary?.scan_coverage?.by_type || {};
  const vulnByType = summary?.vulnerability_breakdown_by_type || {};
  const projectComponents = byType.project || 0;
  const systemComponents = byType.system || 0;
  const extensionComponents = byType.extension || 0;
  const projectVulns = vulnByType.project || 0;
  const systemVulns = vulnByType.system || 0;
  const extensionVulns = vulnByType.extension || 0;
  return [
    "Coverage check",
    `- Project: ${projectComponents} components, ${projectVulns} vulnerabilities`,
    `- System: ${systemComponents} components, ${systemVulns} vulnerabilities`,
    `- Extensions: ${extensionComponents} components, ${extensionVulns} vulnerabilities`
  ].join("\n");
}

function formatSourceStatus(summary) {
  const sourceCoverage = summary?.source_coverage || {};
  const entries = ["Intelligence source status"];
  for (const sourceName of ["osv", "nvd", "ghsa", "sonatype"]) {
    const info = sourceCoverage[sourceName] || {};
    const status = String(info.status || "unknown").toUpperCase();
    const reason = info.reason ? ` (${info.reason})` : "";
    entries.push(`- ${sourceName.toUpperCase()}: ${status}${reason}`);
  }
  return entries.join("\n");
}

let latestSummary = null;
let heartbeatTimer = null;
let isRunning = false;
const progressStages = [
  "Collecting components",
  "Scanning system packages and developer applications",
  "Scanning VS Code extensions",
  "Scanning JetBrains IDE and plugins",
  "Scanning project dependencies from selected directory",
  "Starting advisory synchronization",
  "Syncing OSV advisories",
  "Syncing NVD advisories",
  "Syncing GHSA advisories",
  "Syncing Sonatype advisories",
  "Syncing KEV catalog",
  "Writing reports"
];
let currentStageIndex = -1;

function setStatus(kind, text) {
  const node = document.getElementById("statusPill");
  node.className = `status ${kind}`;
  node.textContent = text;
}

function syncButtons() {
  document.getElementById("runBtn").disabled = isRunning;
  document.getElementById("stopBtn").disabled = !isRunning;
}

function setProgress(stageText, stageIndex) {
  const bar = document.getElementById("progressBar");
  const text = document.getElementById("progressText");
  const safeIndex = Math.max(0, stageIndex);
  const pct = Math.min(100, Math.round(((safeIndex + 1) / progressStages.length) * 100));
  bar.style.width = `${pct}%`;
  text.textContent = stageText;
}

function updateHint() {
  const runProfile = document.getElementById("runProfile").value;
  const scan = document.getElementById("scan").value;
  const projectPath = document.getElementById("projectPath").value.trim();
  if (!projectPath && (scan === "project" || scan === "all" || runProfile === "full" || runProfile === "quick" || runProfile === "power")) {
    setText("hint", "Project path selection is required. Use Browse to pick your repository root.");
    return;
  }
  if (runProfile === "full" && scan === "all") {
    setText("hint", "Recommended public default: no API key required. Optional keys improve source coverage and rate limits.");
    return;
  }
  if (runProfile === "power") {
    setText("hint", "Power-user mode: add GITHUB_TOKEN and NVD_API_KEY for better coverage, freshness, and rate limits.");
    return;
  }
  if (runProfile === "offline") {
    setText("hint", "Offline mode uses local advisory database only (no external API calls).");
    return;
  }
  setText("hint", "");
}

function syncScanForProfile() {
  const scanNode = document.getElementById("scan");
  scanNode.disabled = false;
}

async function hydrateDefaultProjectPath() {
  try {
    const detectedPath = await window.desktopScanner.detectProjectPath();
    if (detectedPath) {
      document.getElementById("projectPath").value = detectedPath;
    }
  } catch (_err) {
    // Keep manual value if detection fails.
  }
}

document.getElementById("browsePathBtn").addEventListener("click", async () => {
  const chosen = await window.desktopScanner.browseProjectPath();
  if (!chosen) return;
  document.getElementById("projectPath").value = chosen;
  updateHint();
});

document.getElementById("buildBtn").addEventListener("click", async () => {
  const cmd = await window.desktopScanner.buildCommand(readProfile());
  setText("command", cmd);
});

document.getElementById("runBtn").addEventListener("click", async () => {
  const profile = readProfile();
  if (!profile.projectPath && (profile.scan === "all" || profile.scan === "project")) {
    setStatus("error", "Path required");
    setText("results", "Select a project folder via Browse before running project/all scans.");
    return;
  }
  setText("logs", "Starting scan...\n");
  isRunning = true;
  syncButtons();
  currentStageIndex = 0;
  setProgress("Starting scan", 0);
  setStatus("running", "Running");
  let elapsed = 0;
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(() => {
    elapsed += 1;
    setStatus("running", `Running (${elapsed}s)`);
  }, 1000);
  const result = await window.desktopScanner.runScan(profile);
  clearInterval(heartbeatTimer);
  isRunning = false;
  syncButtons();
  latestSummary = result.summary;
  if (result.code !== 0) {
    setStatus("error", "Failed");
    setText("results", `Scan failed (exit ${result.code}).\n\n${result.stderr}`);
    return;
  }
  if (!latestSummary) {
    setStatus("error", "No summary");
    setText("results", "Scan completed but report summary could not be parsed. Check logs and retry.");
    return;
  }
  setStatus("success", "Completed");
  setProgress("Completed", progressStages.length - 1);
  const coverageSummary = formatCoverageSummary(result.summary);
  setText("results", `${coverageSummary}\n\nRaw summary\n${JSON.stringify(result.summary, null, 2)}`);
  setText("sourceStatus", formatSourceStatus(result.summary));
});

document.getElementById("stopBtn").addEventListener("click", async () => {
  const result = await window.desktopScanner.stopScan();
  clearInterval(heartbeatTimer);
  isRunning = false;
  syncButtons();
  if (result?.stopped) {
    setStatus("error", "Stopped");
    setProgress("Stopped by user", Math.max(0, currentStageIndex));
    setText("results", "Scan stopped by user.");
    return;
  }
  setStatus("idle", "Idle");
  setProgress("Idle", Math.max(0, currentStageIndex));
  setText("results", result?.reason || "No running scan.");
});

window.desktopScanner.onLog((line) => {
  const logs = document.getElementById("logs");
  logs.textContent += line;
  const match = line.match(/\[progress\]\s+(.*)/);
  if (match) {
    const stage = match[1].trim();
    const idx = progressStages.indexOf(stage);
    if (idx >= 0) {
      currentStageIndex = idx;
      setProgress(stage, idx);
    } else {
      setProgress(stage, Math.max(0, currentStageIndex));
    }
  }
});

document.getElementById("openJson").addEventListener("click", async () => {
  const target = latestSummary?.output_paths?.json || latestSummary?.report_path;
  if (!target) return;
  await window.desktopScanner.openPath(target);
});

document.getElementById("openHtml").addEventListener("click", async () => {
  const target = latestSummary?.output_paths?.html || latestSummary?.html_report_path;
  if (!target) return;
  await window.desktopScanner.openPath(target);
});

document.getElementById("openVulnHtml").addEventListener("click", async () => {
  const target = latestSummary?.output_paths?.vulnerabilities_html || latestSummary?.vuln_fixes_report_path;
  if (!target) return;
  await window.desktopScanner.openPath(target);
});

document.getElementById("openEpssHtml").addEventListener("click", async () => {
  const target = latestSummary?.output_paths?.epss_remediation_html || latestSummary?.epss_remediation_report_path;
  if (!target) return;
  await window.desktopScanner.openPath(target);
});

hydrateDefaultProjectPath();
["runProfile", "scan"].forEach((id) => {
  document.getElementById(id).addEventListener("input", updateHint);
  document.getElementById(id).addEventListener("change", updateHint);
});
document.getElementById("runProfile").addEventListener("change", () => {
  syncScanForProfile();
  updateModeGuide();
});
syncScanForProfile();
updateHint();
updateModeGuide();
syncButtons();
setProgress("Waiting to start", 0);
