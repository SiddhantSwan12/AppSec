// Proves the custom Semgrep ruleset actually works, in both directions:
//
//   1. Every finding-mapped rule fires on the intentionally vulnerable lab.
//      A rule that never matches anything is not a guardrail, it is decoration.
//   2. No rule fires on the secure application. This is the gate that CI
//      enforces on every change.
//
// The lab is a labelled corpus, so the ruleset can be regression-tested the
// same way the application is. Semgrep has no Windows build, so the container
// image is used when the binary is not on PATH.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const LAB = "apps/api/src/lab";
const SECURE = [
  "apps/api/src/app.ts",
  "apps/api/src/auth.ts",
  "apps/api/src/security.ts",
  "apps/api/src/transfers.ts",
  "apps/api/src/detections.ts",
  "apps/api/src/throttle.ts",
  "apps/api/src/audit.ts",
  "apps/api/src/db.ts",
  "apps/api/src/config.ts",
  "apps/api/src/seed.ts",
  "apps/web/src",
];

// Each rule here must catch its finding in the lab. The preventive rules are
// deliberately absent: they guard bugs this codebase does not have.
const expected = {
  "sw-sql-string-interpolation": "SW-03",
  "sw-record-lookup-without-owner-predicate": "SW-01",
  "sw-admin-route-missing-role-check": "SW-02",
  "sw-html-response-interpolation": "SW-04",
  "sw-writable-protected-attribute": "SW-05",
  "sw-non-positive-amount-accepted": "SW-06",
  "sw-conditional-row-lock": "SW-07",
  "sw-conditional-transaction-boundary": "SW-07",
  "sw-money-route-ignores-idempotency-key": "SW-08",
};

const useDocker = process.argv.includes("--docker") || !onPath();

function onPath() {
  const probe = spawnSync("semgrep", ["--version"], { encoding: "utf8" });
  return probe.status === 0;
}

function scan(targets) {
  const args = [
    "--config",
    "semgrep/rules",
    "--json",
    "--quiet",
    "--metrics",
    "off",
    "--disable-version-check",
    ...targets,
  ];
  const result = useDocker
    ? spawnSync(
        "docker",
        [
          "run",
          "--rm",
          "-v",
          `${process.cwd().replace(/\\/g, "/")}:/src`,
          "-w",
          "/src",
          "semgrep/semgrep:latest",
          "semgrep",
          ...args,
        ],
        { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
      )
    : spawnSync("semgrep", args, {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
      });

  if (result.error || result.stdout === undefined)
    throw new Error(
      `Could not run Semgrep. Install it, or ensure Docker is running for the container fallback.\n${result.error ?? ""}`,
    );
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error(
      `Semgrep did not return JSON.\n${result.stdout?.slice(0, 500)}\n${result.stderr?.slice(0, 2000)}`,
    );
  }
  if (parsed.errors?.length)
    for (const error of parsed.errors)
      console.warn(`  semgrep note: ${error.message ?? JSON.stringify(error)}`);
  return parsed.results ?? [];
}

const report = {
  generated_at: new Date().toISOString(),
  runner: useDocker ? "docker semgrep/semgrep" : "semgrep on PATH",
  detection: [],
  secure_findings: [],
  outcome: "failed",
};

console.log(`Semgrep ruleset verification (${report.runner})\n`);

console.log("1. Detection: every mapped rule must fire on the lab corpus.");
const labResults = scan([LAB]);
const byRule = new Map();
for (const finding of labResults) {
  const id = finding.check_id.split(".").pop();
  byRule.set(id, (byRule.get(id) ?? 0) + 1);
}
let missing = 0;
for (const [rule, finding] of Object.entries(expected)) {
  const hits = byRule.get(rule) ?? 0;
  if (hits === 0) missing++;
  report.detection.push({ rule, finding, hits, detected: hits > 0 });
  console.log(
    `   ${hits > 0 ? "PASS" : "FAIL"}  ${rule.padEnd(46)} ${finding}  ${hits} hit(s)`,
  );
}

console.log("\n2. Gate: no rule may fire on the secure application.");
const secureResults = scan(SECURE);
for (const finding of secureResults) {
  const entry = {
    rule: finding.check_id.split(".").pop(),
    file: path.relative(process.cwd(), finding.path).replace(/\\/g, "/"),
    line: finding.start?.line,
  };
  report.secure_findings.push(entry);
  console.log(`   FAIL  ${entry.rule}  ${entry.file}:${entry.line}`);
}
if (secureResults.length === 0) console.log("   PASS  no findings.");

report.outcome =
  missing === 0 && secureResults.length === 0 ? "passed" : "failed";
mkdirSync("docs/evidence", { recursive: true });
writeFileSync(
  "docs/evidence/semgrep-verification.json",
  JSON.stringify(report, null, 2),
);

console.log(
  `\n${report.outcome}: ${Object.keys(expected).length - missing}/${Object.keys(expected).length} rules detected their finding, ${secureResults.length} finding(s) on the secure application.`,
);
console.log("Report: docs/evidence/semgrep-verification.json");
process.exitCode = report.outcome === "passed" ? 0 : 1;
