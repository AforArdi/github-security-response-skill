import os
import sys
import json
import base64
import hashlib
import re
import subprocess
import requests

def get_token():
    return subprocess.check_output(["gh", "auth", "token"]).decode().strip()

token = get_token()
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

representative_repos = [
    "AforArdi/backend-one",
    "AforArdi/dragon-news-nextjs",
    "AforArdi/bpl-auction-react",
    "AforArdi/wanderlust-server",
    "AforArdi/passkeeper",
    "AforArdi/better-auth-app",
    "AforArdi/assignment-two",
    "AforArdi/nextjs-dragon-news",
    "AforArdi/freeCodeCampJs",
    "AforArdi/world-heritage-2026"
]

print("=== Analyzing Representatives for Malware Signatures ===")

samples = {}

for repo in representative_repos:
    print(f"\nScanning tree for {repo}...")
    res = requests.get(f"https://api.github.com/repos/{repo}/git/trees/main?recursive=1", headers=headers)
    if res.status_code != 200:
        # Try checking default branch from repo info
        r_info = requests.get(f"https://api.github.com/repos/{repo}", headers=headers).json()
        def_b = r_info.get("default_branch", "main")
        res = requests.get(f"https://api.github.com/repos/{repo}/git/trees/{def_b}?recursive=1", headers=headers)
    
    if res.status_code == 200:
        tree = res.json().get("tree", [])
        sus_paths = [
            i["path"] for i in tree 
            if i["type"] == "blob" and (
                i["path"] in ["api.js", "api.json", "debug_api.json"] or
                i["path"].endswith("/api.js") or
                ".vscode/" in i["path"] or
                "fonts/" in i["path"] or
                i["path"].startswith("public/fonts") or
                "postcss.config" in i["path"] or
                "next.config" in i["path"] or
                "eslint.config" in i["path"] or
                i["path"] == "package.json"
            )
        ]
        print(f"Found {len(sus_paths)} potential target files in {repo}:")
        for p in sus_paths:
            print(f"  - {p}")
            if p not in samples:
                # Fetch content
                c_res = requests.get(f"https://api.github.com/repos/{repo}/contents/{p}", headers=headers)
                if c_res.status_code == 200:
                    c_json = c_res.json()
                    raw_b64 = c_json.get("content", "")
                    try:
                        raw_bytes = base64.b64decode(raw_b64)
                        sha256 = hashlib.sha256(raw_bytes).hexdigest()
                        samples[p] = {
                            "repo": repo,
                            "path": p,
                            "size": len(raw_bytes),
                            "sha256": sha256,
                            "content_bytes": raw_bytes
                        }
                    except Exception as e:
                        print(f"    Failed to decode {p}: {e}")

print(f"\nCollected {len(samples)} distinct file paths across representative repos.")

# Detailed analysis of samples
signatures = {}
for path, data in samples.items():
    raw = data["content_bytes"]
    sha256 = data["sha256"]
    
    # Check if text
    is_text = True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        is_text = False
        text = raw.decode("utf-8", errors="ignore")
    
    analysis = {
        "repo": data["repo"],
        "path": path,
        "size": data["size"],
        "sha256": sha256,
        "is_text": is_text
    }
    
    # Extract patterns
    if path.endswith(".ttf") or path.endswith(".woff") or path.endswith(".woff2") or path.endswith(".svg") or path.endswith(".eot"):
        magic_4 = raw[:4].hex()
        is_js = text.startswith("(function") or "eval(" in text or "function" in text
        analysis["type"] = "fake_font_payload"
        analysis["magic_4_hex"] = magic_4
        analysis["starts_with_js_function"] = is_js
        analysis["preview"] = text[:150]
        # Look for IPs / strings in text
        ips = re.findall(r'\b(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\b', text)
        analysis["extracted_ips"] = list(set(ips))
        
    elif path.endswith(".json") and ".vscode" in path:
        analysis["type"] = "vscode_config"
        try:
            cfg = json.loads(text)
            analysis["parsed_keys"] = list(cfg.keys())
            analysis["is_malicious"] = False
            if "tasks" in cfg:
                for t in cfg["tasks"] if isinstance(cfg["tasks"], list) else [cfg["tasks"]]:
                    if isinstance(t, dict):
                        if t.get("runOptions", {}).get("runOn") == "folderOpen" or "fa-brands" in t.get("command", "") or "api.js" in t.get("command", ""):
                            analysis["is_malicious"] = True
                            analysis["malicious_task_command"] = t.get("command")
            if cfg.get("task.allowAutomaticTasks") is True:
                analysis["is_malicious"] = True
                analysis["allowAutomaticTasks"] = True
        except Exception as e:
            analysis["parse_error"] = str(e)
            
    elif path.endswith("api.js"):
        analysis["type"] = "api_js_dropper"
        analysis["has_mock_exports"] = "export const api" in text or "export const login" in text
        analysis["has_obfuscated_boot"] = "(function boot(" in text or "splitLane(" in text or "spin(" in text
        analysis["extracted_ips"] = list(set(re.findall(r'\b(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\.(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]?\d)\b', text)))
        
    elif "postcss.config" in path or "next.config" in path or "eslint.config" in path:
        analysis["type"] = "config_injection"
        lines = text.split("\n")
        trailing_injected = []
        for idx, line in enumerate(lines, 1):
            if len(line) > 200 and ("function(" in line or "var z =" in line or "\\x" in line):
                trailing_injected.append((idx, len(line), line[:60] + " ... " + line[-60:]))
        analysis["trailing_injections"] = trailing_injected
        
    elif path.endswith("README.md") and "fonts" in path:
        analysis["type"] = "fake_font_readme"
        analysis["has_blockchain_explorer"] = "Blockchain Explorer" in text or "custom fonts" in text
        
    elif path == "package.json":
        analysis["type"] = "package_json"
        try:
            pkg = json.loads(text)
            scripts = pkg.get("scripts", {})
            bad_scripts = {}
            for s_k, s_v in scripts.items():
                if isinstance(s_v, str) and ("node api.js" in s_v or "debug_api" in s_v):
                    bad_scripts[s_k] = s_v
            analysis["bad_scripts"] = bad_scripts
        except Exception as e:
            analysis["parse_error"] = str(e)

    signatures[path] = analysis

# Print summary
print("\n=== Analyzed Indicators Summary ===")
for p, a in sorted(signatures.items()):
    t = a.get("type", "unknown")
    size = a.get("size", 0)
    sha = a.get("sha256", "")[:12]
    extra = ""
    if t == "fake_font_payload":
        extra = f"JS={a.get('starts_with_js_function')} Magic={a.get('magic_4_hex')} IPs={a.get('extracted_ips')}"
    elif t == "vscode_config":
        extra = f"Malicious={a.get('is_malicious')} Cmd={a.get('malicious_task_command', '')[:40]}"
    elif t == "api_js_dropper":
        extra = f"MockExp={a.get('has_mock_exports')} Boot={a.get('has_obfuscated_boot')} IPs={a.get('extracted_ips')}"
    elif t == "config_injection":
        extra = f"Injections={len(a.get('trailing_injections', []))}"
    elif t == "package_json":
        extra = f"BadScripts={list(a.get('bad_scripts', {}).keys())}"
    print(f"[{t}] {p} ({size} B, {sha}...) {extra}")
