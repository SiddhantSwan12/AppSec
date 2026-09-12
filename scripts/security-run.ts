import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
const lab = process.argv.includes("--lab");
const config = JSON.parse(await readFile("security-runner/rules.json", "utf8"));
if (lab) {
  config.base_url = "http://127.0.0.1:4001";
  config.origin = config.base_url;
  await writeFile(
    "security-runner/lab-rules.json",
    JSON.stringify(config, null, 2),
  );
}
const python =
  process.platform === "win32"
    ? ".venv/Scripts/python.exe"
    : ".venv/bin/python";
if (!existsSync(python))
  throw new Error(
    "Create .venv and install security-runner/requirements.txt first.",
  );
const result = spawnSync(
  python,
  [
    "security-runner/runner.py",
    "--config",
    lab ? "security-runner/lab-rules.json" : "security-runner/rules.json",
    "--output",
    lab ? "docs/evidence/lab" : "docs/evidence/secure",
  ],
  { stdio: "inherit", env: process.env },
);
process.exitCode = result.status ?? 2;
