# Incident Response Operational Checklist

**Incident Identifier**: `INC-[YYYYMMDD]-[ACCOUNT]`  
**Lead Investigator**: `[NAME / CALLSIGN]`  
**Date Initiated**: `[YYYY-MM-DD]`  
**Target Account / Scope**: `[ACCOUNT NAME]`  

---

## Stage 1: Preliminary Containment & Reconnaissance (Read-Only)

- [ ] **1.1 Identity & Access Verification**
  - [ ] Execute `gh auth status` without printing or capturing secrets.
  - [ ] Confirm authorized account name matches investigation target.
  - [ ] Verify token scopes (`repo`, `read:org`). Do not expose credential strings.
  - [ ] Establish dedicated investigation workspace directory outside target project checkouts.
- [ ] **1.2 Complete Repository Inventory**
  - [ ] Paginate completely through all accessible repositories (`/user/repos?per_page=100&affiliation=owner,organization_member,collaborator`).
  - [ ] Rigorously segregate personally owned repositories from organization and collaborator-owned repositories.
  - [ ] Record metadata: full name, visibility (public/private), default branch, archived status, push timestamp, and current branch tip SHA.
  - [ ] Save inventory to `repository-inventory.json` and `repository-inventory.csv`.
- [ ] **1.3 Push Surge & Anomaly Analysis**
  - [ ] Analyze commit author timestamps vs committer timestamps across target window.
  - [ ] Identify suspicious automated batch push surges (e.g. dozens of repositories pushed within minutes).
  - [ ] Identify discrepancies where commit history was amended with backdated timestamps.
  - [ ] Query and record baseline GitHub API rate limit quota (`/rate_limit`).

---

## Stage 2: Malware Analysis & Signature Validation (Read-Only)

- [ ] **2.1 Representative Sample Deep Dive**
  - [ ] Select 5–10 representative repositories exhibiting the suspicious push window.
  - [ ] Retrieve file trees via Git Tree API (`/git/trees/{sha}?recursive=1`).
  - [ ] Inspect `.vscode/tasks.json` and `.vscode/settings.json` for automatic execution triggers (`runOn: folderOpen`, `task.allowAutomaticTasks: true`).
  - [ ] Inspect asset files for disguised scripts (e.g. check font magic bytes vs ASCII JavaScript).
  - [ ] Inspect root modules (`api.js`, `server.js`) and package lifecycle hooks (`package.json` scripts).
  - [ ] Inspect build and bundler configurations (`postcss.config.*`, `next.config.*`, `eslint.config.*`) for hidden whitespace-padded payloads.
- [ ] **2.2 Signature Formulation & False-Positive Hardening**
  - [ ] Calculate cryptographic hashes (SHA-256) and exact file sizes for confirmed payloads.
  - [ ] Define negative rules to protect legitimate assets (e.g., true binary font magic bytes `00 01 00 00`, legitimate linter tasks, legitimate env templates).
  - [ ] Test signatures against clean repositories to verify zero false positives.
  - [ ] Document verified signatures in `malware-signatures.json` and false-positive boundaries in `false-positives.md`.
- [ ] **2.3 Full-Scope Tree Scan**
  - [ ] Scan 100% of in-scope repositories against validated signatures using read-only API requests.
  - [ ] Classify every repository into: `CONFIRMED MALICIOUS`, `CLEAN`, `SUSPICIOUS`, or `INCOMPLETE`.
  - [ ] Generate `repository-findings.csv` and telemetry checkpoints.

---

## Stage 3: Remediation Planning & Patch Preparation (Pre-Execution Gate)

- [ ] **3.1 Surgical Patch Generation**
  - [ ] For modified configuration files (`package.json`, `settings.json`, `postcss.config.mjs`), prepare clean replacement files in a local `patches/` directory.
  - [ ] Verify that patches remove 100% of malicious injections while preserving all legitimate developer settings, dependencies, and scripts.
  - [ ] Perform non-destructive AST and syntax validation on all clean replacement patches.
- [ ] **3.2 Machine-Readable Manifest Creation**
  - [ ] Build `remediation-manifest.json` cataloging every single proposed action (`DELETE` or `MODIFY`).
  - [ ] Record target repository, file path, original SHA-256, expected replacement patch, and confidence level.
  - [ ] Reconcile total action counts (verify deletion count + modification count == total actions).
- [ ] **3.3 Tracked Environment File Discovery**
  - [ ] Audit all default-branch trees for pre-existing tracked `.env` or secret files.
  - [ ] Record path, size, and risk rating in `tracked-environment-files.csv` without reading or logging secret contents.
  - [ ] Flag critical live secret exposures for provider-level revocation.
- [ ] **3.4 Formal Authorization Gate**
  - [ ] Present remediation manifest, scope boundaries, and findings summary to repository owner.
  - [ ] Obtain explicit written authorization prior to executing any remote changes.

---

## Stage 4: Authorized Bulk Remediation Execution (Atomic Git Operations)

- [ ] **4.1 Pre-Modification Live Gate Verification**
  - [ ] For each repository, query live default-branch tip SHA (`/git/refs/heads/{branch}`).
  - [ ] Verify that live branch tip exactly matches the expected parent SHA.
  - [ ] If branch tip has diverged, abort operation on that repository and flag for review.
- [ ] **4.2 Atomic Tree Mutation & Commit Creation**
  - [ ] Upload clean replacement files as Git blobs (`POST /git/blobs`).
  - [ ] Construct new Git tree (`POST /git/trees`) setting malicious paths to `sha: null` and pointing modified paths to clean blob SHAs.
  - [ ] Create atomic commit (`POST /git/commits`) with descriptive message and verified expected parent commit.
  - [ ] Update branch reference using compare-and-swap (`PATCH /git/refs/heads/{branch}` with `force: false`).
- [ ] **4.3 Checkpoint & Rate Limit Telemetry**
  - [ ] Record per-repository execution status in `remediation-execution-log.csv`.
  - [ ] Check remaining rate limit quota after each batch; stop if quota falls below safety margin (1,000 requests).
  - [ ] Update `cleanup-checkpoint.json` after every processed repository to support seamless resume.

---

## Stage 5: Post-Commit Verification & Hardening

- [ ] **5.1 Post-Commit Tree Validation**
  - [ ] Query new default-branch tree via read-only API.
  - [ ] Confirm parent linkage matches expected prior commit.
  - [ ] Confirm 100% absence of targeted malicious file paths.
  - [ ] Confirm clean patch content is active and uncorrupted.
  - [ ] Record verification outcome in `post-remediation-verification.csv`.
- [ ] **5.2 Security Hardening Enforcement**
  - [ ] Ensure `.gitignore` ignores environment secrets (`.env`, `.env.*`) while whitelisting templates (`!.env.example`, `!.env.sample`, `!.env.template`).
  - [ ] Ensure `.gitignore` ignores local editor workspaces (`.vscode/`).
  - [ ] Completely purge tracked `.vscode/` directories from Git trees.
  - [ ] Execute atomic hardening commits and perform post-commit tree validation.

---

## Stage 6: Credential Revocation & Post-Incident Containment

- [ ] **6.1 Credential Revocation & Provider Rotation**
  - [ ] Revoke existing GitHub Personal Access Tokens (PATs) and OAuth authorizations.
  - [ ] Generate new fine-grained GitHub PAT with minimal necessary scopes and short expiration.
  - [ ] Rotate all secrets, database credentials, and API keys found in tracked `.env` files.
- [ ] **6.2 Account & Key Audit**
  - [ ] Review all authorized SSH keys (`/user/keys`) and remove unrecognized keys.
  - [ ] Review repository deploy keys, GitHub Apps, and webhook subscriptions.
  - [ ] Audit account security log (`https://github.com/settings/security-log`).
- [ ] **6.3 Workstation & Host Audit**
  - [ ] Audit developer workstation for automated task execution artifacts (check processes, startup tasks, shell profiles).
  - [ ] Clear editor workspace cache and disable automatic task execution globally (`"task.allowAutomaticTasks": false`).
  - [ ] Synchronize local repository clones by pulling clean remote branches (`git pull origin <default-branch>`).
