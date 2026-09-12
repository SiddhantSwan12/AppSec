// Produces a CycloneDX SBOM for the installed dependency tree.
//
// The lockfile records what should be installed; the SBOM records what is, in a
// format a vulnerability feed can be replayed against later. When a CVE lands
// on a transitive package six months from now, the question "were we shipping
// it, and at which version" should not require rebuilding an old commit.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

const out = "docs/evidence/sbom.cdx.json";

// Run through a shell, because Node refuses to execute npm's .cmd shim without
// one. The command is passed as a single literal string rather than as an args
// array: with `shell: true` Node concatenates array arguments without escaping
// them, which is a real injection hazard in general and a deprecation warning
// here. Nothing in this string is interpolated.
const result = spawnSync(
  "npm sbom --sbom-format cyclonedx --sbom-type application --omit dev",
  { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: true },
);

if (result.status !== 0) {
  console.error(result.stderr || "npm sbom failed.");
  process.exit(1);
}

let document;
try {
  document = JSON.parse(result.stdout);
} catch {
  console.error("npm sbom did not return JSON.");
  process.exit(1);
}

mkdirSync("docs/evidence", { recursive: true });
writeFileSync(out, JSON.stringify(document, null, 2));

const components = document.components?.length ?? 0;
console.log(`CycloneDX ${document.specVersion ?? "?"} SBOM written to ${out}`);
console.log(`${components} runtime components recorded.`);
console.log(
  "Python dependencies are locked separately in security-runner/requirements.lock.txt.",
);
