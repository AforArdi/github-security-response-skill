#!/usr/bin/env python3
import sys
import json
import base64
import time
import re
import requests
from collections import defaultdict
from datetime import datetime

# ==============================================================================
#      🛡️ ULTIMATE GITHUB SECURITY & PACKAGE.JSON / FONT CLEANER (v5.0)
# ==============================================================================
# Targets:
# 1. PACKAGE.JSON TRIGGER SANITIZATION:
#    - Finds "dev": "node api.js && vite", "node api.js && next dev", etc.
#    - Automatically strips out "node api.js &&" and updates package.json on GitHub!
# 2. ROOT api.js & api.json:
#    - Completely removes the malicious dropper file from GitHub root!
# 3. DEEP FONT MALWARE:
#    - Deletes all fa-solid-*, fa-regular-*, fa-brands-* (.woff2, .woff, .ttf, .eot, .svg)
#    - Deletes fake "Blockchain Explorer" README.md files
# 4. .VSCODE AUTO-RUN BACKDOORS:
#    - Deletes .vscode/tasks.json and infected .vscode/settings.json
# 5. CONFIG OBFUSCATION:
#    - Cleans or flags postcss.config.*, eslint.config.*, next.config.*
# 6. MULTI-BRANCH & MULTI-REPO:
#    - Scans ALL repositories (Owner, Org, Collaborator) & ALL branches
# ==============================================================================

print("=" * 85)
print("   🛡️  ULTIMATE GITHUB SECURITY: PACKAGE.JSON, ROOT API.JS & DEEP FONT CLEANER (v5.0)   ")
print("=" * 85)

token = input("Enter your GitHub Personal Access Token (PAT): ").strip()
if not token:
    print("[-] Token cannot be empty!")
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

user_res = requests.get("https://api.github.com/user", headers=headers)
if user_res.status_code != 200:
    print(f"[-] Authentication failed! HTTP Status: {user_res.status_code}")
    print("[-] Please ensure your token has 'repo' (Full control) permissions.")
    sys.exit(1)

current_user = user_res.json().get("login")
print(f"[✓] Authenticated successfully as: {current_user}")

print("\n[+] Fetching all repository lists (Personal + Organizations + Collaborations)...")
repos = []
page = 1
while True:
    url = f"https://api.github.com/user/repos?per_page=100&page={page}&affiliation=owner,organization_member,collaborator"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        break
    data = res.json()
    if not data or not isinstance(data, list):
        break
    repos.extend(data)
    page += 1

print(f"[✓] Total {len(repos)} repositories found to scan.\n")

MALICIOUS_PATTERNS = [
    "193.247.144",       # C2 Server IP
    "global['_V']",      # C2 Execution payload
    "global['!']",       # C2 execution payload
    "global[\"_V\"]",
    "global[\"!\"]",
    "fromCharCode",      # Obfuscation
    "\\x",               # Hex obfuscation
    "child_process",     # Unauthorized shell execution
    "reverse_shell",
    "/bin/sh",
    "/bin/bash",
    "curl http",
    "wget http",
    "Blockchain Explorer application"
]

def is_content_malicious(text):
    for pattern in MALICIOUS_PATTERNS:
        if pattern in text:
            return True, pattern
    return False, None

def get_file_content_from_github(repo_name, path, branch):
    """GitHub API থেকে ফাইলের Base64 কনটেন্ট সেফলি ডিকোড করে পড়ে"""
    c_url = f"https://api.github.com/repos/{repo_name}/contents/{path}?ref={branch}"
    c_res = requests.get(c_url, headers=headers)
    if c_res.status_code == 200:
        c_data = c_res.json()
        raw_b64 = c_data.get("content", "")
        try:
            content_str = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            return content_str, c_data.get("sha")
        except Exception:
            return None, c_data.get("sha")
    return None, None

infected_report = defaultdict(list)
all_clean_repos = []

for idx, repo in enumerate(repos, start=1):
    repo_name = repo["full_name"]
    print(f"\n[{idx}/{len(repos)}] 🔍 Scanning Repo: {repo_name}")

    # ব্রাঞ্চ ফেচ করা (Pagination সহ)
    branches_to_scan = []
    b_page = 1
    while True:
        branches_url = f"https://api.github.com/repos/{repo_name}/branches?per_page=100&page={b_page}"
        b_res = requests.get(branches_url, headers=headers)
        if b_res.status_code == 200:
            b_data = b_res.json()
            if isinstance(b_data, list) and len(b_data) > 0:
                for b in b_data:
                    branches_to_scan.append(b["name"])
                b_page += 1
            else:
                break
        else:
            break

    if not branches_to_scan:
        default_b = repo.get("default_branch", "main")
        branches_to_scan = [default_b]

    priority = ["project-setup", "development", "dev", "main", "master", "production"]
    branches_to_scan.sort(key=lambda x: priority.index(x) if x in priority else 99)

    repo_had_infection = False

    for branch in branches_to_scan:
        tree_url = f"https://api.github.com/repos/{repo_name}/git/trees/{branch}?recursive=1"
        tree_res = requests.get(tree_url, headers=headers)
        if tree_res.status_code != 200:
            continue

        tree_items = tree_res.json().get("tree", [])
        for item in tree_items:
            path = item.get("path", "")
            sha = item.get("sha")

            if path == "package.json" or path.endswith("/package.json"):
                pkg_content, pkg_sha = get_file_content_from_github(repo_name, path, branch)
                if pkg_content and ("api.js" in pkg_content or "debug_api" in pkg_content):
                    try:
                        pkg_json = json.loads(pkg_content)
                        modified = False
                        if "scripts" in pkg_json and isinstance(pkg_json["scripts"], dict):
                            for s_name, s_cmd in list(pkg_json["scripts"].items()):
                                if isinstance(s_cmd, str) and ("api.js" in s_cmd or "debug_api" in s_cmd):
                                    clean_cmd = re.sub(r'\s*(&&|;|&|;)?\s*node\s+(?:\.\/)?(?:debug_)?api(?:\.js)?\s*(&&|;|&|;)?\s*', ' ', s_cmd, flags=re.IGNORECASE)
                                    clean_cmd = re.sub(r'^\s*(&&|;|&|;)\s*', '', clean_cmd).strip()
                                    clean_cmd = re.sub(r'\s*(&&|;|&|;)\s*$', '', clean_cmd).strip()

                                    if clean_cmd != s_cmd:
                                        pkg_json["scripts"][s_name] = clean_cmd
                                        modified = True
                                        print(f"   [!] TRIGGER FOUND in {path} [{s_name}]: '{s_cmd}' -> Sanitized to: '{clean_cmd}'")

                        if modified:
                            new_content = json.dumps(pkg_json, indent=2) + "\n"
                            b64_content = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
                            put_url = f"https://api.github.com/repos/{repo_name}/contents/{path}"
                            put_res = requests.put(put_url, headers=headers, json={
                                "message": "security: sanitize malicious node api.js script from package.json",
                                "content": b64_content,
                                "sha": pkg_sha or sha,
                                "branch": branch
                            })
                            if put_res.status_code in [200, 201]:
                                print(f"       [✓] Cleaned & Updated {path} on GitHub (Branch: {branch})\n")
                                infected_report[f"{repo_name} [{branch}]"].append(f"Sanitized {path} ('node api.js' trigger removed)")
                                repo_had_infection = True
                                time.sleep(0.4)
                            else:
                                print(f"       [-] Failed to update {path} (HTTP {put_res.status_code}): {put_res.text}\n")
                    except Exception as err:
                        print(f"   [-] Error parsing package.json in {repo_name}: {err}")
            should_delete = False
            reason = ""

            if path in ["api.js", "./api.js", "api.json"]:
                should_delete = True
                reason = f"Malicious root {path} dropper"

            elif any(fa in path for fa in ["fa-solid-", "fa-regular-", "fa-brands-"]):
                should_delete = True
                reason = "Fake FontAwesome malware payload"
            elif "/public/fonts/" in path or path.startswith("public/fonts/"):
                if path.endswith(".woff2") or path.endswith(".woff") or path.endswith(".ttf") or path.endswith(".eot") or path.endswith(".svg"):
                    should_delete = True
                    reason = "Suspicious font in nested public/fonts"
                elif path.endswith("README.md"):
                    content, real_sha = get_file_content_from_github(repo_name, path, branch)
                    if content and ("Blockchain Explorer" in content or "custom fonts" in content):
                        should_delete = True
                        reason = "Fake font Blockchain Explorer README"
                        sha = real_sha or sha

            elif path == "debug_api.json" or path.endswith("/debug_api.json"):
                should_delete = True
                reason = "Malicious debug_api.json payload"
            elif path in ["config.bat", "run.bat"] or (path.endswith(".bat") and ("malware" in path or "temp" in path)):
                should_delete = True
                reason = "Malicious Windows batch script"
            elif path.endswith("/nul") or path == "nul":
                should_delete = True
                reason = "Windows nul exploit file"

            elif path in [".vscode/tasks.json", ".vscode/settings.json"]:
                content, real_sha = get_file_content_from_github(repo_name, path, branch)
                if content:
                    if "fa-solid-" in content or "woff2" in content or "runOn" in content or "193.247" in content or "fonts" in content or "api.js" in content:
                        should_delete = True
                        reason = f"Infected {path} (auto-run backdoor)"
                        sha = real_sha or sha

            elif path in ["postcss.config.mjs", "postcss.config.js", "eslint.config.js", "eslint.config.mjs", "next.config.js", "next.config.mjs"]:
                content, real_sha = get_file_content_from_github(repo_name, path, branch)
                if content:
                    is_bad, matched = is_content_malicious(content)
                    if is_bad:
                        should_delete = True
                        reason = f"Etherhiding injected {path} (Matched: {matched})"
                        sha = real_sha or sha

            if should_delete and sha:
                print(f"   [!] ALERT: Found [{reason}]")
                print(f"       -> Target: {repo_name} | Branch: {branch} | Path: {path}")
                print(f"       -> Deleting from GitHub...")

                del_url = f"https://api.github.com/repos/{repo_name}/contents/{path}"
                del_res = requests.delete(del_url, headers=headers, json={
                    "message": f"security: remove {reason} ({path})",
                    "sha": sha,
                    "branch": branch
                })

                if del_res.status_code in [200, 204]:
                    print(f"       [✓] Successfully DELETED from GitHub! (Branch: {branch})\n")
                    infected_report[f"{repo_name} [{branch}]"].append(f"{path} ({reason})")
                    repo_had_infection = True
                    time.sleep(0.35)
                else:
                    print(f"       [-] Failed to delete (HTTP {del_res.status_code}): {del_res.text}\n")

    if not repo_had_infection:
        all_clean_repos.append(repo_name)

print("\n" + "=" * 85)
print("                       FINAL SECURITY AUDIT REPORT                       ")
print("=" * 85)

if infected_report:
    print(f"🚨 SANITIZED & REMOVED THREATS ({len(infected_report)} Repositories/Branches):\n")
    for r_branch, files in infected_report.items():
        print(f"📁 {r_branch}:")
        for f in files:
            print(f"   └── ❌ [RESOLVED] {f}")
        print("-" * 85)
else:
    print("✅ All scanned repositories, branches, package.json scripts and font folders are 100% CLEAN!")

print(f"\nTotal Clean Repositories: {len(all_clean_repos)}/{len(repos)}")

log_filename = f"github_cleanup_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(log_filename, "w", encoding="utf-8") as lf:
    lf.write("=" * 85 + "\n")
    lf.write(f"GITHUB SECURITY CLEANUP AUDIT REPORT - {datetime.now().isoformat()}\n")
    lf.write(f"Scanned by user: {current_user}\n")
    lf.write("=" * 85 + "\n\n")

    if infected_report:
        lf.write(f"RESOLVED THREATS & INJECTIONS ({len(infected_report)}):\n\n")
        for r_branch, files in infected_report.items():
            lf.write(f"Repository / Branch: {r_branch}\n")
            for f in files:
                lf.write(f"  - [RESOLVED] {f}\n")
            lf.write("\n")
    else:
        lf.write("ALL REPOSITORIES CLEAN. NO THREATS OR INJECTIONS FOUND.\n")

print(f"\n📄 Complete audit report saved to file: {log_filename}")
print("=" * 85)
