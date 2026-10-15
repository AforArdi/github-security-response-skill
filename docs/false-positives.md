# False-Positive Guidance & Safe Remediation Boundaries

**Document Version**: 1.0  
**Target Scope**: GitHub Multi-Repository Incident Response  
**Purpose**: Define positive evidence requirements and negative validation boundaries to prevent destructive over-remediation of legitimate developer assets.

---

## 1. The Dangers of Filename-Only & Keyword Matching

A fundamental failure mode in automated repository cleanup is deleting files based solely on their filename, directory name, or generic keyword hits.

> [!CAUTION]
> **STRICT SAFETY RULE**: Never delete or modify a repository file based on filename, path, extension, or single keyword match alone. Every finding must be verified against concrete structural, cryptographic, or format-level criteria.

Examples of destructive over-remediation caused by naïve matching:
- Deleting legitimate FontAwesome or web font files because their name matches `fa-brands-400.ttf` or `fonts/`.
- Deleting legitimate `.vscode/tasks.json` or `.vscode/settings.json` containing developer build tasks (`tsc --watch`, `npm test`) or database connections (`sqltools`).
- Deleting legitimate API utility modules (`api.js`, `api.ts`, `server/api.js`) used for frontend HTTP client routing.
- Stripping legitimate package scripts because they contain the word `node` or chained commands (`&&`).

---

## 2. True Fonts vs. Disguised JavaScript Payloads

### Legitimate Binary Font Specifications
Genuine web and desktop fonts are binary container files defined by open standards. They start with distinct binary magic bytes and contain structured font tables:

| Font Format | Valid Extensions | Standard Magic Bytes (Hex) | ASCII Representation |
| :--- | :--- | :--- | :--- |
| **TrueType Font** | `.ttf` | `00 01 00 00` | `\x00\x01\x00\x00` |
| **OpenType Font** | `.otf`, `.ttf` | `4F 54 54 4F` | `OTTO` |
| **WOFF 1.0** | `.woff` | `77 4F 46 46` | `wOFF` |
| **WOFF 2.0** | `.woff2` | `77 4F 46 32` | `wOF2` |
| **Embedded OpenType** | `.eot` | Variable header; bytes 8–11 contain `4C 50` (`LP`) | MicroType OS/2 header |

### Malicious Impersonation Pattern
In the documented incident, `fa-brands-400.ttf` was **not** a binary font:
- **Magic Bytes**: `28 66 75 6e` (ASCII `(fun` from `(function`).
- **File Type**: Pure ASCII / UTF-8 text containing obfuscated JavaScript.
- **Size & Hash**: Exact size `27,525 bytes`, SHA-256 `b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea`.

### Validation Decision Gate
To safely distinguish genuine fonts from malicious payloads:
```python
def is_fake_font_payload(content_bytes: bytes) -> bool:
    # 1. Check for genuine binary font magic bytes
    if content_bytes.startswith(b'\x00\x01\x00\x00') or content_bytes.startswith(b'OTTO'):
        return False  # Legitimate binary TrueType/OpenType font
    if content_bytes.startswith(b'wOFF') or content_bytes.startswith(b'wOF2'):
        return False  # Legitimate binary WOFF font
        
    # 2. Check for confirmed script indicator
    if content_bytes.startswith(b'(function') or b'(function boot(' in content_bytes:
        return True   # Confirmed disguised JavaScript payload
        
    return False
```

---

## 3. Legitimate VS Code Configurations (.vscode/)

VS Code workspaces legitimately use `.vscode/tasks.json` and `.vscode/settings.json` for developer productivity.

### Legitimate Developer Patterns:
1. **`tasks.json`**:
   - `type: "npm"`, `type: "shell"` executing standard scripts (`npm run build`, `npm test`, `cargo build`).
   - `group: "build"` or `group: "test"`.
   - Normal presentation (`reveal: "always"` or `reveal: "silent"`).
   - Tasks executed on manual command rather than automatic folder load.
2. **`settings.json`**:
   - Local database connection definitions (`sqltools.connections` configured for local PostgreSQL or MySQL).
   - Language server and linter rules (`editor.formatOnSave: true`, `eslint.enable: true`).
   - Formatting and indentation preferences.

### Compromise Indicator Profile:
- **`tasks.json`**: Task masquerading as `eslint-check` with `"runOptions": {"runOn": "folderOpen"}` and `"presentation": {"reveal": "never"}` executing a shell command that invokes `node` against a font file.
- **`settings.json`**: Injects `"task.allowAutomaticTasks": true` and `"debug.openDebug": "neverOpen"` to suppress user prompts.

### Safe Remediation Boundary:
- If `.vscode/tasks.json` contains *only* the malicious task, the file should be deleted. If legitimate build tasks exist, remove *only* the malicious task object from the `tasks` array.
- If `.vscode/settings.json` contains legitimate developer configuration, **never delete the file**. Prune only the malicious auto-task permission keys (`task.allowAutomaticTasks`).
- When performing account-wide hardening to permanently disallow workspace-level tasks, ensure developers understand that personal workspace settings should reside in user global settings (`%APPDATA%\Code\User\settings.json`) or that `.vscode/` should be ignored via `.gitignore`.

---

## 4. Legitimate API Helper Modules (api.js / api.ts)

Many frontend JavaScript frameworks include an `api.js` or `api.ts` file in the root or `src/` directory.

### Legitimate Helper Structure:
- Standard Axios instance initialization (`axios.create({ baseURL: ... })`).
- Fetch wrappers with error interceptors and TypeScript interfaces.
- Next.js API route handlers or Express router exports.
- Clean formatting without massive horizontal whitespace padding.

### Compromise Indicator Profile:
- File size typically exceeds 24,000 bytes.
- Begins with mock boilerplate exports (`status: 200`, `mock-token`).
- Line 16 contains `export default api;` followed by **200+ space characters** pushing the payload off-screen.
- Trailing block contains obfuscated Node.js bootstrapping code (`var z = '-10846'`, `boot(global, require)`).

---

## 5. Legitimate Package Scripts & Build Configurations

### Legitimate Developer Scripts:
- Node.js invocations in `package.json`:
  ```json
  "dev": "node server.js",
  "build": "tsc && vite build",
  "start": "node dist/index.js"
  ```

### Compromise Indicator Profile:
- Injected prefix prepending arbitrary execution before legitimate tooling:
  ```json
  "dev": "node api.js && vite",
  "start": "node api.js && node dist/server.js"
  ```

### Safe Remediation Boundary:
- Use surgical regex replacement: remove only `node api.js && ` or `node debug_api.js && ` from script strings.
- Never reset `package.json` to an older Git revision, as doing so would discard legitimate dependency upgrades, new scripts, and metadata added by developers.
- For `postcss.config.mjs` or `eslint.config.js`, preserve all legitimate plugin declarations (e.g. `@tailwindcss/postcss`, `autoprefixer`) and strip only trailing whitespace padding and appended obfuscated code.
