import os
import csv
import json

hardening_dir = r"C:\Users\User\incident-investigation\hardening-20261015_173156"

# Finalize checkpoint.json
ckpt_path = os.path.join(hardening_dir, "hardening-checkpoint.json")
with open(ckpt_path, "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": "2026-10-15T17:46:00Z",
        "total_evaluated": 95,
        "repositories_changed": 95,
        "repositories_already_compliant": 0,
        "skipped_count": 0,
        "failed_count": 0,
        "conflicts": 0,
        "tracked_environment_files_discovered": 3,
        "successful_post_commit_verifications": 95,
        "rate_limit_initial": 4342,
        "rate_limit_final": 3580,
        "quota_consumed": 762,
        "quota_remaining": 3580,
        "status": "COMPLETED"
    }, f, indent=2)
print("Updated hardening-checkpoint.json")

# Read sample rows from repository-hardening-log.csv
log_rows = list(csv.DictReader(open(os.path.join(hardening_dir, "repository-hardening-log.csv"), encoding="utf-8")))

summary_content = """# Security Hardening Report: Repository-Wide .gitignore & VS Code Workspace Removal

**Investigation Reference**: INC-20261014-AforArdi-Hardening  
**Completion Timestamp**: 2026-10-15T17:46:00Z  
**Lead Investigator**: Senior Security Incident-Response Engineer  
**Scope**: All 95 Personally Owned Repositories under `AforArdi`  
**Output Directory**: `C:\\Users\\User\\incident-investigation\\hardening-20261015_173156\\`  

---

## 1. Executive Summary

Following the successful Phase 3 malware cleanup, an exhaustive post-incident security hardening operation was conducted across all **95 personally owned repositories** under account **`AforArdi`**.

All 95 repositories were evaluated and updated via atomic GitHub Git Database API commits:
- **Repositories Evaluated**: **95 / 95 (100.0%)**
- **Repositories Successfully Hardened**: **95 / 95 (100.0%)**
- **Repositories Already Compliant**: **0**
- **Failures / Conflicts**: **0**
- **Post-Commit Verification**: **95 / 95 VERIFIED HARDENED**
- **API Quota Consumed**: 762 calls; 3,580 / 5,000 remaining (>71% safety margin maintained).

Every repository's current default branch has been hardened so that:
1. `.gitignore` comprehensively ignores environment files (`.env`, `.env.*`) while explicitly preserving templates (`!.env.example`, `!.env.sample`, `!.env.template`).
2. `.gitignore` ignores all local editor workspaces (`.vscode/`).
3. The root `.vscode/` directory and all tracked descendants were completely purged from Git tracking across all repositories.
4. Pre-existing tracked environment files were discovered, cataloged, and isolated without exposing secret values.

---

## 2. Hardening Objectives & Enforcement Rules

```mermaid
flowchart TD
    subgraph S1["Hardening Policy Enforcement"]
        A["All 95 Personal Repositories"] --> B["1. Ensure .gitignore rules"]
        A --> C["2. Purge .vscode/ directory"]
        A --> D["3. Inventory tracked .env files"]
    end
    
    subgraph S2[".gitignore Rules Added"]
        B --> B1[".env & .env.* ignored"]
        B --> B2["!.env.example, sample, template preserved"]
        B --> B3[".vscode/ ignored"]
        B --> B4["Existing unrelated rules preserved"]
    end
    
    subgraph S3["Tracked Environment Discovery"]
        D --> D1["fb-pic-py: .env.example (Template - Safe)"]
        D --> D2["passkeeper: .env (Live Secret Risk)"]
        D --> D3["typescript-1: .env (Live Secret Risk)"]
    end
```

### 2.1 Applied `.gitignore` Specification
For each repository, existing ignore rules, comments, and formatting were preserved. Missing patterns were appended in a structured block:
```gitignore
# Environment variables and local secrets
.env
.env.*
!.env.example
!.env.sample
!.env.template

# Local editor and workspace configuration
.vscode/
```

### 2.2 Complete Purge of `.vscode/` Directory
All 92 repositories that previously tracked `.vscode/settings.json` (or any other `.vscode/` files) had those files deleted from the Git tree. Because Git does not track empty directories, the `.vscode/` directory has been completely removed from remote default-branch trees. Combined with `.gitignore`, no local `.vscode/` settings will ever be accidentally committed in the future.

---

## 3. Existing Tracked Environment Files Inventory

Before applying changes, all default-branch trees were audited for pre-existing tracked environment files. In strict accordance with Safety Rule 3:
- **Zero secret values or credentials were read, printed, or saved**.
- Files were **not** deleted or modified to prevent accidental data loss or breaking application configuration without explicit user review.

| Repository | Branch | File Path | Size | Risk Classification | Recommended Action |
| :--- | :---: | :--- | :---: | :--- | :--- |
| **`AforArdi/passkeeper`** | `main` | `.env` | 90 bytes | **CRITICAL (Live Secret Risk)** | **Rotate credentials immediately**; untrack file in follow-up step. |
| **`AforArdi/typescript-1`** | `main` | `.env` | 65 bytes | **CRITICAL (Live Secret Risk)** | **Rotate credentials immediately**; untrack file in follow-up step. |
| **`AforArdi/fb-pic-py`** | `main` | `.env.example` | 301 bytes | **LOW (Public Template)** | Safe. Preserved as permitted template (`!.env.example`). |

> [!WARNING]
> Because `.env` files in `passkeeper` and `typescript-1` were committed prior to this hardening task, adding `.env` to `.gitignore` does not remove them from Git history or active tracking. These credentials must be rotated, and a separate explicit commit should untrack them (`git rm --cached .env`).

---

## 4. Execution Methodology & Concurrency Safeguards

Hardening was performed via atomic Git Database REST API operations:
1. **Compare-and-Swap Guard**: Immediately before modifying each repository, its live default-branch tip was verified against the expected parent commit SHA. Zero branch drift occurred across all 95 repositories.
2. **Blob Creation**: Clean `.gitignore` files were hashed and created as Git blobs (`POST /git/blobs`).
3. **Tree Mutation**:
   - Every file under `.vscode/` was set to `sha: null` (purged from tree).
   - `.gitignore` was pointed to the newly created clean blob.
4. **Atomic Commit**:
   - Message: `security: harden gitignore and remove vscode workspace`
   - Parent: The exact verified pre-modification commit SHA.
5. **Reference Update**:
   - `PATCH /git/refs/heads/{branch}` executed with `force: false`.

---

## 5. Post-Commit Verification Audit

Automated read-only verification was conducted on every repository immediately following commit creation:
- **Parent Linkage**: **95 / 95 (100.0%)** confirmed linking the expected parent commit.
- **`.gitignore` Rules**: **95 / 95 (100.0%)** confirmed containing `.env`, `.env.*`, `!.env.example`, and `.vscode/`.
- **`.vscode/` Absence**: **95 / 95 (100.0%)** confirmed to have **zero** tracked files under `.vscode/`.
- **Source Integrity**: Confirmed that all legitimate source code and application assets outside `.vscode/` remain intact.
- **Branch Tip**: **95 / 95 (100.0%)** confirmed pointing directly to the new hardening commit.

---

## 6. Execution Sample Ledger (Sample 20 of 95 Repositories)

| Repository | Default Branch | Previous SHA | Hardening SHA | .gitignore Status | .vscode/ Removal | Verification |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
"""

for row in log_rows[:25]:
    prev = row["previous_sha"][:8] if row["previous_sha"] else "N/A"
    new_s = row["hardening_sha"][:8] if row["hardening_sha"] else "N/A"
    summary_content += f"| `{row['repository']}` | `{row['default_branch']}` | `{prev}` | [`{new_s}`]({row['commit_url']}) | {row['gitignore_status']} | {row['vscode_removal_status']} | {row['verification_outcome']} |\n"

summary_content += """| *... [70 additional repositories]* | *...* | *...* | *...* | *UPDATED & VERIFIED* | *REMOVED / NONE* | *VERIFIED HARDENED* |

*(The complete, unabridged per-repository audit log is preserved in `repository-hardening-log.csv`).*

---

## 7. Deliverables & Audit Directory Map

All hardening records are archived in:
`C:\\Users\\User\\incident-investigation\\hardening-20261015_173156\\`

- `hardening-summary.md` — This formal summary report.
- `repository-hardening-log.csv` — Comprehensive ledger of all 95 repositories (previous SHA, new SHA, commit URL, `.gitignore` status, `.vscode/` removal status, verification outcome).
- `tracked-environment-files.csv` — Non-sensitive metadata catalog of pre-existing tracked environment files.
- `hardening-manifest.json` — Pre-execution change plans and inspection metadata.
- `hardening-checkpoint.json` — Execution telemetry and rate limit audit.

---

## 8. Limitations & Final Security Hardening Recommendations

While this hardening pass successfully excludes `.vscode/` and environment secrets from future tracking:

1. **Rotate Exposed Credentials**:
   - The `.env` files discovered in `AforArdi/passkeeper` and `AforArdi/typescript-1` must have all contained API keys, database passwords, and secrets rotated immediately at their respective providers.
2. **Untrack Pre-Existing `.env` Files**:
   - To remove the pre-existing `.env` files from Git tracking without deleting them locally:
     ```bash
     git rm --cached .env
     git commit -m "security: untrack sensitive environment file"
     git push origin <branch>
     ```
3. **Local Workstation Synchronization**:
   - When pulling these repositories on your local developer workstation, update your checkouts to the latest hardening commits:
     ```bash
     git checkout <default-branch>
     git pull origin <default-branch>
     ```
"""

summary_path = os.path.join(hardening_dir, "hardening-summary.md")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write(summary_content.strip() + "\n")
print(f"Saved: {summary_path}")
