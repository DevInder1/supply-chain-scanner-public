#!/usr/bin/env node

const { spawnSync } = require("child_process");

const PIP_PACKAGE = "devinder-supply-chain-scanner";

function resolvePython() {
  const candidates = process.platform === "win32" ? ["python", "py"] : ["python3", "python"];
  for (const cmd of candidates) {
    const probe = spawnSync(cmd, ["--version"], { stdio: "ignore" });
    if (probe.status === 0) {
      return cmd;
    }
  }
  return null;
}

function hasInstalledPackage(python) {
  const probe = spawnSync(
    python,
    ["-c", `import importlib.util; raise SystemExit(0 if importlib.util.find_spec("scanner") else 1)`],
    { stdio: "ignore" }
  );
  return probe.status === 0;
}

const python = resolvePython();
if (!python) {
  console.error("Python 3.10+ is required.");
  console.error("Install from https://www.python.org/downloads/ and retry.");
  process.exit(1);
}

if (!hasInstalledPackage(python)) {
  console.error(`Python package '${PIP_PACKAGE}' is not installed.`);
  console.error(`Run: pip install ${PIP_PACKAGE}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const child = spawnSync(python, ["-m", "scanner.main", ...args], { stdio: "inherit" });
if (typeof child.status === "number") {
  process.exit(child.status);
}
process.exit(1);
