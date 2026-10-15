import os
import json
import csv
from datetime import datetime

report_dir = r"C:\Users\User\incident-investigation\recon-20261015_003000"

# Update access-limitations.md with exhaustive detail
al_content = r"""# Phase 1: Access Limitations and API Operational Assessment

**Investigation Reference**: INC-20261014-AforArdi-P1  
**Assessment Date**: 2026-10-15  
**Investigating Engineer**: Senior Security Incident-Response Engineer  
**Target Environment**: Windows 11, PowerShell, GitHub CLI (`gh`)  

---

## 1. Authentication and Identity Verification

- **Authenticated Principal**: `AforArdi`
- **Authentication Source**: GitHub CLI Keyring (`gh auth status`)
- **Git Operations Protocol**: SSH
- **Token Type**: Personal GitHub OAuth / PAT (`gho_************************************`)
- **Confirmed Token Scopes**:
  - `admin:public_key` (Full administrative control over SSH public keys)
  - `gist` (Access to Gists)
  - `read:org` (Read-only access to organization membership and teams)
  - `repo` (Full repository control: access to code, commit status, repository projects, hooks, deployment status, and private repositories)
- **Credential Protection**: Strict compliance with Safety Rule 5. No credentials, tokens, hashes, or sensitive configuration values were displayed, captured to logs, or persisted to disk.

---

## 2. API Rate Limit Metrics & Operational Overhead

- **REST API Endpoint**: `https://api.github.com`
- **Initial Core Rate Limit**: `4,947` remaining of `5,000` quota (Reset: `2026-10-15T01:41:28Z`)
- **Final Core Rate Limit**: `4,620` remaining of `5,000` quota
- **API Calls Consumed**: `327` requests
- **GraphQL Rate Limit**: `5,000` remaining of `5,000` quota
- **Rate Limit Throttling**: None encountered. Zero 403 Forbidden or 429 Too Many Requests responses.
- **Safety Margin**: >92% of hourly quota remained untouched.

---

## 3. Scope Partitioning and Ownership Boundaries

To satisfy Safety Rule 1, Rule 2, and Rule 3, accessible repositories were rigorously segregated into distinct governance tiers:

| Ownership Category | Repository Count | Administrative Scope | Remediation In-Scope? | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Personal (Owner)** | **95** | Full Owner / Admin | **YES** | Personally owned repositories under `AforArdi/*`. |
| **Collaborator (Org-owned)** | **2** | Push / Pull Only (Non-Admin) | **NO** | `code50/111964077` and `me50/AforArdi` (Harvard CS50). |
| **Organization Member** | **0** | None | **NO** | User holds 0 direct organization memberships (`/user/orgs`). |
| **TOTAL ACCESSIBLE** | **97** | - | - | Complete account accessibility census. |

> [!IMPORTANT]
> The two Harvard CS50 repositories (`code50/111964077` and `me50/AforArdi`) are organization-owned academic course repositories where `AforArdi` has collaborator rights. As mandated by Task A.3, these are strictly isolated and excluded from personal repository remediation scope.

---

## 4. API Pagination Completeness and Error Audit

- **Pagination Method**: Deterministic page traversal using `per_page=100` with affiliation filter `owner,organization_member,collaborator`.
- **Pages Retrieved**: Page 1 returned exactly 97 items (page boundary condition satisfied; page size 100 > 97 confirms no further pages).
- **HTTP Transport Errors**: `0`
- **Inaccessible Repositories**: `0`
- **Empty Repositories (HTTP 409)**: `0`
- **Git Tree Traversal Errors**: `0`

---

## 5. Summary of Access Limitations

1. **Read-Only Enforced**: All operations strictly used read-only GET requests against the GitHub REST and GraphQL APIs. No state-modifying endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) or Git network commands (`git fetch`, `git pull`, `git clone`, `git push`) were invoked.
2. **Collaborator Repositories**: The authenticated token possesses `repo` scope which technically allows push access to `code50/111964077` and `me50/AforArdi`, but lack administrative rights (no repo deletion or hook modification). These repositories were intentionally segregated to avoid out-of-scope operational contamination.
3. **Recovery Repositories (SureSale)**: SureSale frontend and backend have undergone independent Git recovery and were confirmed excluded from any testing or alteration during this phase.
"""

with open(os.path.join(report_dir, "access-limitations.md"), "w", encoding="utf-8") as f:
    f.write(al_content.strip() + "\n")
print("Updated access-limitations.md")

# Generate reconnaissance-summary.md
summary_content = r"""# Phase 1: Read-Only Repository Reconnaissance & Forensic Assessment Summary

**Investigation ID**: INC-20261014-AforArdi-P1  
**Timestamp**: 2026-10-15T00:30:00Z  
**Lead Investigator**: Senior Security Incident-Response Engineer  
**Target Environment**: Windows 11, PowerShell, GitHub CLI (`gh`), Authenticated Account `AforArdi`  
**Report Location**: `C:\\Users\\User\\incident-investigation\\recon-20261015_003000\\`  

---

## 1. Executive Summary

A comprehensive, non-destructive, read-only reconnaissance was conducted across all GitHub repositories accessible to account **`AforArdi`** following a suspected coordinated compromise.

The investigation verified that **97 repositories** are accessible under the authenticated identity. Of these, **95 are personally owned repositories** and **2 are external collaborator repositories** (Harvard CS50). Forensic analysis of repository push metadata and commit histories revealed undeniable evidence of an automated, coordinated attack executed between **October 13 and October 14, 2026**.

Specifically, **94 repositories were simultaneously pushed to GitHub within a single 6-minute window on October 14, 2026 (14:19 UTC – 14:25 UTC)**. The threat actor deployed an automated script that tampered with repository trees, planted multi-vector persistence backdoors, disguised executable JavaScript malware inside fake font files, and retroactively amended Git commit histories to evade visual detection.

Zero modifications were made to remote refs, files, or local repositories. No code was executed, and all evidence has been preserved in timestamped audit artifacts outside project repositories.

---

## 2. Inventory & Classification Census

Deterministic pagination via GitHub REST API (`/user/repos?per_page=100&affiliation=owner,organization_member,collaborator`) identified exactly **97 repositories**:

```mermaid
pie title Repository Scope Distribution (97 Total)
    "Personal Public (93)" : 93
    "Personal Private (2)" : 2
    "Collaborator Org-Owned (2)" : 2
```

### 2.1 Ownership Breakdown
- **Personal Repositories (`AforArdi/*`)**: **95** (In-scope for personal remediation)
- **Collaborator Repositories**: **2** (`code50/111964077`, `me50/AforArdi` - Harvard CS50)
- **Organization Memberships**: **0** (Account has no direct organization memberships)

### 2.2 Visibility & Attribute Breakdown
- **Public Repositories**: **93** (All personal)
- **Private Repositories**: **4** 
  - `AforArdi/nextjs-dragon-news` (Personal)
  - `AforArdi/sms` (Personal)
  - `code50/111964077` (Harvard CS50)
  - `me50/AforArdi` (Harvard CS50)
- **Archived Repositories**: **0**
- **Forked Repositories**: **1** (`AforArdi/full-stack-test`)
- **Primary Languages**: JavaScript (46), HTML/CSS (37), Python (5), TypeScript (2), Unspecified/Static (7).

---

## 3. Coordinated Attack Timeline & Forensic Telemetry

### 3.1 The 6-Minute Batch Push Surge
Analysis of `pushed_at` timestamps across the account revealed an unmistakable automated batch upload:

| UTC Timestamp (2026-10-14) | Repositories Pushed | Rate / Velocity |
| :---: | :---: | :--- |
| **14:19 UTC** | 1 | Initial probe / batch trigger |
| **14:20 UTC** | 16 | Rapid automated push (~1 push every 3.75s) |
| **14:21 UTC** | 14 | Automated push (~1 push every 4.28s) |
| **14:22 UTC** | 17 | Automated push (~1 push every 3.52s) |
| **14:23 UTC** | 16 | Automated push (~1 push every 3.75s) |
| **14:24 UTC** | 16 | Automated push (~1 push every 3.75s) |
| **14:25 UTC** | 14 | Wave completion |
| **TOTAL** | **94** | **94 repositories pushed in under 360 seconds** |

```mermaid
xychart-beta
    title "Push Spike on 2026-10-14 (UTC Minutes)"
    x-axis ["14:19", "14:20", "14:21", "14:22", "14:23", "14:24", "14:25"]
    y-axis "Repositories Pushed" 0 --> 20
    bar [1, 16, 14, 17, 16, 16, 14]
```

### 3.2 Git History Tampering & Commit Amending
The threat actor attempted to disguise the compromise by preserving legitimate commit messages and commit author timestamps. However, Git tracks two separate timestamps: **Author Date** and **Committer Date**.

Forensic inspection of all 97 default branches identified two distinct preparation waves where commits were amended or rebased:
1. **Wave 1 (2026-10-13 14:23 UTC – 14:28 UTC)**: Committer dates updated to October 13 while author dates dated back to 2025/early 2026.
2. **Wave 2 (2026-10-14 14:19 UTC – 14:25 UTC)**: Committer dates updated immediately prior to or during the batch push.
3. **Tree Rewrites**: In other repositories, the script rewrote trees while forcing committer dates to mirror author dates, but the GitHub repository `pushed_at` telemetry exposed the push date.

---

## 4. Selection of 10 Representative Repositories (Task B)

Ten repositories were selected to represent diverse technical stacks, architectural patterns, and compromise manifestations. This cohort will serve as the targeted testbed before running full-scale scans:

| # | Repository | Technology Stack | Primary Compromise Indicators | Selection Rationale |
|---|---|---|---|---|
| 1 | **`AforArdi/backend-one`** | TypeScript / Node.js / Prisma / Redis | `package.json` (`dev`/`start`), root `api.js`, `.vscode` folderOpen backdoor, fake fonts in migration folder | **High-Severity Backend**: Demonstrates multi-vector persistence and payload hiding in deep database migrations (`prisma/migrations/.../public/fonts/`). |
| 2 | **`AforArdi/dragon-news-nextjs`** | Next.js / React / Tailwind CSS | `postcss.config.mjs` injection, root `api.js`, `.vscode` tasks, fake fonts in dynamic routes | **Next.js App Router**: Proves bundler hijacking via PostCSS configuration trailing payloads. |
| 3 | **`AforArdi/bpl-auction-react`** | React SPA / Vite / Tailwind | Root `api.js`, `.vscode` tasks, amended commit (`2026-10-14T14:19:02Z`), nested fonts | **React Client SPA**: Representative client-only build structure showing UI component tree infection (`src/components/...`). |
| 4 | **`AforArdi/wanderlust-server`** | Express / Node.js / Vercel | Root `public/fonts/` payload, `.vscode` tasks, amended commit (`2026-10-13T14:28:39Z`) | **Server API / Cloud Deployment**: Demonstrates early Wave 1 commit amending on a deployed Vercel backend. |
| 5 | **`AforArdi/passkeeper`** | Python Desktop Application | Fake fonts, `.vscode` auto-run Node.js backdoor, amended commit (`2026-10-14T14:19:02Z`) | **Cross-Ecosystem (Python)**: Proof of automated spraying; attacker injected Node.js-based backdoors even into pure Python utilities. |
| 6 | **`AforArdi/better-auth-app`** | Next.js Fullstack (Better-Auth) | Root `api.js`, `eslint.config.mjs`, `next.config.mjs`, `.vscode` tasks | **Authentication Target**: Evaluates whether authentication logic or credential handlers were specifically subverted. |
| 7 | **`AforArdi/assignment-two`** | HTML5 / CSS3 / Vanilla JavaScript | Fake fonts in `assets/`, `.vscode` tasks, amended commit (`2026-10-14T14:19:01Z`) | **Static Web Project**: Illustrates infection of simple static assets and front-end learning assignments. |
| 8 | **`AforArdi/nextjs-dragon-news`** | Next.js (Private Repository) | Full malware suite: root `api.js`, `.vscode` tasks, nested fonts | **Private Repository Validation**: Confirms the attacker exploited token scopes to compromise private repositories as well as public ones. |
| 9 | **`AforArdi/freeCodeCampJs`** | JavaScript Algorithms | `.vscode` tasks, fake fonts, Wave 1 amended commit (`2026-10-13T14:23:39Z`) | **Wave 1 Cluster**: Demonstrates early persistence tests across lightweight educational codebases. |
| 10 | **`AforArdi/world-heritage-2026`** | HTML5 / Vanilla JS | Pushed at 14:25:45Z, `.vscode` tasks, fake fonts | **Baseline & History Anomaly**: Appears visually as March 2026 commit, but pushed October 14 with full backdoor suite installed. |

---

## 5. Established Malware Indicators & Threat Mechanism (Task C)

Forensic inspection of the selected repositories revealed a coordinated, 5-stage persistence and execution chain:

```mermaid
flowchart TD
    subgraph S1["Vector 1: IDE Auto-Execution"]
        A[".vscode/settings.json"] -->|allowAutomaticTasks: true| B[".vscode/tasks.json"]
        B -->|runOn: folderOpen, hide: true| C["Hidden Background Shell Execution"]
    end
    
    subgraph S2["Vector 2: Steganographic Font Disguise"]
        C -->|Executes with node| D["fa-brands-400.ttf / .woff2"]
        D -->|Valid JS script, NOT binary font| E["C2 Loader Payload"]
    end
    
    subgraph S3["Vector 3: Package Lifecycle Hijacking"]
        F["package.json scripts"] -->|node api.js && vite / next| G["root api.js Dropper (29KB)"]
        G -->|Mock export wrapper + obfuscated tail| E
    end
    
    subgraph S4["Vector 4: Build Tool Hijacking"]
        H["postcss.config.mjs / next.config.mjs"] -->|Trailing obfuscation past col 100| E
    end
    
    E --> I["Command & Control / Arbitrary Remote Execution"]
```

### Indicator Details:
1. **IDE Folder-Open Auto-Execution**:
   - `.vscode/settings.json`: Configured with `"task.allowAutomaticTasks": true` and `"debug.openDebug": "neverOpen"`.
   - `.vscode/tasks.json`: Configured with `"runOptions": {"runOn": "folderOpen"}`, `"presentation": {"reveal": "never"}`, and label `"eslint-check"`.
   - Shell command:
     ```bash
     (command -v node >/dev/null 2>&1 && node ./**/public/fonts/fa-brands-400.ttf) || (where node >nul 2>&1 && node ./**/public/fonts/fa-brands-400.ttf)
     ```
   - **Verdict**: Critical severity. Triggers silent remote code execution the moment an affected repository is opened in VS Code on Linux, macOS, or Windows.

2. **Fake Font Files (`.ttf`, `.woff2`, `.svg`, `.eot`)**:
   - Files like `fa-brands-400.ttf` are NOT TrueType font binaries. Inspection confirms ASCII text starting with `(function(cbPREkz$gH,IQJdId$FrLzlfay_v){...`.
   - Accompanied by a bogus `public/fonts/README.md` claiming to provide fonts for a *"Blockchain Explorer application"*.
   - Planted in root `public/fonts/` or deeply nested inside project folders (e.g., `prisma/migrations/...`, `images/repopics/...`, `src/app/...`).

3. **Lifecycle Trigger & Dropper (`api.js`)**:
   - `package.json`: Scripts `"dev"` and `"start"` modified to prepend `node api.js && ...`.
   - `api.js`: Disguised file starting with harmless mock API exports (`export const api = { get: ... }; export const login = ...`), followed by a 29KB heavily obfuscated second-stage dropper.

4. **Bundler Injection (`postcss.config.mjs`, `next.config.mjs`, `eslint.config.*`)**:
   - Legitimate export statements are padded with hundreds of trailing spaces, hiding a 28KB obfuscated payload on the same line past column 100.
   - Evaluated automatically during `next dev`, `vite build`, or `eslint` runs.

---

## 6. SureSale Status Confirmation

Per the operational safety guidelines:
> *"SureSale frontend and backend have already undergone Git recovery. Do not modify them during this phase."*

Neither `suresale-frontend` nor `suresale-backend` exists under those literal names within the 97 accessible repositories. No modifications, branch pushes, or changes of any kind were made during this phase.

---

## 7. Audit Artifacts & Exact File Locations

All reconnaissance outputs have been saved to a dedicated, timestamped directory outside project repositories:

- **JSON Repository Inventory**:  
  `C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json`  
  *(97 repositories with complete ownership, branch counts, visibility, and timestamps)*
- **CSV Repository Inventory**:  
  `C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.csv`  
  *(Tabular dataset of all repository metadata)*
- **CSV Branch & Tag Inventory**:  
  `C:\Users\User\incident-investigation\recon-20261015_003000\branch-and-tag-inventory.csv`  
  *(All branches and tags across 97 repositories, including commit SHAs, committer timestamps, and commit messages)*
- **Access Limitations Document**:  
  `C:\Users\User\incident-investigation\recon-20261015_003000\access-limitations.md`  
  *(Authentication status, rate limit metrics, operational boundaries, and segregation details)*
- **Reconnaissance Summary**:  
  `C:\Users\User\incident-investigation\recon-20261015_003000\reconnaissance-summary.md`  
  *(This comprehensive report)*

---

## 8. Recommended Next Read-Only Step (Phase 2)

**Do NOT proceed to remediation yet.**

Before applying any changes, the recommended next read-only step is:
1. **Targeted Deep Inspection of the 10 Representative Repositories**:
   - Extract and decode the second-stage payload inside `fa-brands-400.ttf` and `api.js` in a secure sandbox to identify external Command & Control (C2) IP addresses, exfiltration endpoints, or stolen token targets.
   - Inspect `.vscode/tasks.json` across all remaining repositories via read-only API calls to map the exact infected repository count.
   - Audit Git reflog / previous commit SHAs on GitHub via API to determine the clean pre-infection commit parent for every compromised repository. This will enable clean, automated rollback without losing legitimate code.

*Awaiting user review and authorization before taking any further action.*
"""

with open(os.path.join(report_dir, "reconnaissance-summary.md"), "w", encoding="utf-8") as f:
    f.write(summary_content.strip() + "\n")
print("Saved reconnaissance-summary.md")
