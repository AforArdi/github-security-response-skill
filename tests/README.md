# Toolkit Testing & Validation Harness

This directory documents non-executing validation, static syntax checking, and safe unit-testing procedures for the GitHub Security Incident Response Toolkit.

> [!CAUTION]
> **STRICT SAFETY RULE**: Never execute operational remediation scripts (`execute_bulk_cleanup_v2.py`, `execute_hardening.py`, or `github_cleaner.py`) during tests. These scripts interact with live GitHub API endpoints and alter remote repository refs. Testing must be performed strictly using static analysis, syntax compilation, or mocked fixtures.

---

## 1. Static Syntax & AST Verification (Non-Executing)

To verify that all toolkit scripts have valid Python syntax and are parseable by Python 3.10+ without executing any code or initializing network connections:

```bash
# Run python compilation verification across all scripts
python -m py_compile ../scripts/*.py
```

Or using an automated Python AST audit:

```python
import os
import ast

scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
errors = []

for fname in os.listdir(scripts_dir):
    if not fname.endswith(".py"):
        continue
    filepath = os.path.join(scripts_dir, fname)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()
    try:
        ast.parse(code, filename=fname)
        print(f"[PASS] {fname}")
    except SyntaxError as e:
        print(f"[FAIL] {fname}: {e}")
        errors.append((fname, str(e)))

if errors:
    raise SystemExit(f"Syntax validation failed for {len(errors)} scripts.")
print("All toolkit scripts passed static AST syntax parsing.")
```

---

## 2. Cryptographic Hash & Manifest Integrity Check

To ensure that no scripts have been altered or corrupted since packaging:

```python
import os
import json
import hashlib

manifest_path = os.path.join(os.path.dirname(__file__), "..", "toolkit-manifest.json")
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
mismatches = []

for entry in manifest["scripts"]:
    filename = entry["filename"]
    filepath = os.path.join(scripts_dir, filename)
    if not os.path.exists(filepath):
        mismatches.append(f"Missing file: {filename}")
        continue
    with open(filepath, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    if file_hash != entry["sha256"]:
        mismatches.append(f"Hash mismatch on {filename}: expected {entry['sha256']}, got {file_hash}")
    else:
        print(f"[VERIFIED] {filename} matches SHA-256")

if mismatches:
    raise SystemExit(f"Integrity check failed:\n" + "\n".join(mismatches))
print("All script hashes match toolkit-manifest.json.")
```

---

## 3. Dependency & Import Surface Audit

All toolkit scripts are built primarily on Python standard library modules (`os`, `sys`, `json`, `csv`, `re`, `hashlib`, `base64`, `subprocess`, `time`, `datetime`). The only required third-party HTTP client dependency is:

- `requests>=2.31.0,<=2.34.2`

To verify that no undeclared third-party dependencies are required:

```python
import os
import ast

scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
detected_imports = set()

for fname in os.listdir(scripts_dir):
    if not fname.endswith(".py"):
        continue
    filepath = os.path.join(scripts_dir, fname)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                detected_imports.add(name.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                detected_imports.add(node.module.split('.')[0])

print(f"Total top-level imports across toolkit: {sorted(detected_imports)}")
```

---

## 4. Mocked Unit Testing for Signatures & Parsers

When adding new signatures to `malware-signatures.json`:
1. **Never use live malicious binaries** in test fixtures.
2. Use synthetic text strings or mock JSON representations.
3. Test against both positive mock payloads (disguised JS in font names, `runOn: folderOpen`) and negative fixtures (legitimate TrueType fonts starting with `\x00\x01\x00\x00`, legitimate WOFF fonts starting with `wOFF`, and clean `.vscode/settings.json` configurations).
4. Assert that the false-positive rule set correctly rejects genuine binary assets.
