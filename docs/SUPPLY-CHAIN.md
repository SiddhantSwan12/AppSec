# Supply chain

Most of this application's code was written by someone else. The dependency tree is larger than the source tree by orders of magnitude, and every package in it runs with the same privileges as the code that imports it. These are the controls over that, and the gaps.

## Controls in place

### Pinning

`package-lock.json` pins every direct and transitive package to an exact version with an integrity hash. `security-runner/requirements.lock.txt` does the same for Python, resolved separately. `compose.yaml` pins images to tags including a digest-bearing minor (`postgres:18-alpine`, `axllent/mailpit:v1.29`) rather than `latest`.

### Install-time execution

CI installs with `npm ci --ignore-scripts`. Lifecycle scripts are the shortest path from a compromised package to code execution on a build machine, and they run before any scanner has looked at anything. Nothing in this tree needs them: `argon2` ships prebuilt binaries for the platforms in use.

This is not on by default for local installs, which is a gap — a developer running plain `npm ci` gets the scripts. Making it the default requires `.npmrc`, and that silently changes behaviour for anyone who clones the repository, so it is documented here rather than imposed.

### Vulnerability scanning

- **`npm audit --audit-level=high`** gates the build. High and critical fail; moderate and below are reported.
- **OSV-Scanner** reads both lockfiles against the OSV database, which covers advisories npm's own feed does not.
- **Trivy** scans the PostgreSQL and Mailpit images for OS-package vulnerabilities. Application dependencies and base-image packages are different supply chains with different feeds, and scanning one proves nothing about the other.
- **Dependabot** opens update pull requests weekly across npm, pip, Docker and GitHub Actions.

Image scanning runs with `exit-code: "0"` deliberately. A base-image CVE with no fixed version available is not something a pull request can act on, and a gate that cannot be satisfied gets bypassed. The findings are reported and reviewed; they do not block.

### Secret scanning

**gitleaks** runs over full history, not just the diff. A credential removed in a later commit is still published. Local demo credentials in `.env.example` are deliberate, documented as local-only, and would be a finding in any real repository.

### SBOM

`npm run sbom` produces a CycloneDX document at `docs/evidence/sbom.cdx.json`, archived by CI for 90 days.

The lockfile records what should be installed. The SBOM records what was, in a format a vulnerability feed can be replayed against later. When an advisory lands on a transitive package months from now, the question "were we shipping it, and at which version" should not require rebuilding an old commit to answer.

## Known gaps

### GitHub Actions are referenced by tag, not commit SHA

`actions/checkout@v5` resolves a mutable tag. Whoever controls that repository can change what the tag points at, and every workflow run picks it up silently — this is how several real Actions compromises have worked.

The fix is to pin every `uses:` to a full commit SHA with the tag in a trailing comment, and let Dependabot maintain them. Dependabot is already configured for the `github-actions` ecosystem to do exactly that.

It is not done here because the SHAs must be resolved from the upstream repositories at pinning time, and writing values that were not verified against the real repositories would produce workflows that look pinned and do not run. To apply it:

```
npx pinact run                      # or: gh api repos/actions/checkout/commits/v5 --jq .sha
```

This is the most significant outstanding item in this document.

### No provenance verification

Package signatures and npm provenance attestations are not checked. `npm audit signatures` verifies registry signatures for packages that publish them and would be the next step.

### The lab has its own tree

The intentionally vulnerable lab shares the dependency tree with the secure application. It is isolated at runtime — separate process, database, port and cookie namespace — but not at install time. Acceptable here because the lab never runs outside a developer machine and never runs in CI's DAST job.

### Transitive trust is not actually verified

Pinning guarantees the same bytes install every time. It says nothing about whether those bytes were safe the first time. Nothing in this project reviews dependency source, and no realistic amount of effort would: the honest control is keeping the tree small, updating promptly, and limiting what install-time code can do.

## Reviewing a Dependabot pull request

1. Read the changelog for behaviour changes, not just the version bump.
2. Check whether the package is in the runtime path or development-only. A `devDependencies` bump cannot affect what is served, but it can affect what the build produces.
3. Confirm CI passes, including `npm run semgrep:verify` — a dependency update that changes how a pattern parses will surface there.
4. For anything touching `argon2`, `pg`, `express` or `zod`, check the security-relevant tests specifically: authentication, transfers and the authorization matrix.
