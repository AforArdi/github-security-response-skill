import os
import sys
import json
import csv
import base64
import subprocess
from datetime import datetime
import requests

# UTF-8 output configuration
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def get_token():
    return subprocess.check_output(["gh", "auth", "token"]).decode().strip()

token = get_token()
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
})

# Load 95 personal repos from Phase 1 inventory
inv_path = r"C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json"
all_repos = json.load(open(inv_path, "r", encoding="utf-8"))
personal_repos = [r for r in all_repos if r.get("ownership_category") == "Personal (Owner)"]

print(f"Loaded {len(personal_repos)} personal repositories.")

# Check current rate limit
rl = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
print(f"Live API Core Rate Limit: {rl.get('remaining')}/{rl.get('limit')} (Reset: {rl.get('reset')})")

timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
hardening_dir = rf"C:\Users\User\incident-investigation\hardening-{timestamp_str}"
os.makedirs(hardening_dir, exist_ok=True)
print(f"Created dedicated hardening report directory: {hardening_dir}")

tracked_env_files = []
repo_plans = []

REQUIRED_RULES = [
    ".env",
    ".env.*",
    "!.env.example",
    "!.env.sample",
    "!.env.template",
    ".vscode/"
]

def analyze_gitignore(existing_content):
    if not existing_content:
        # Create full block
        block = """# Environment variables and local secrets
.env
.env.*
!.env.example
!.env.sample
!.env.template

# Local editor and workspace configuration
.vscode/
"""
        return block, False, REQUIRED_RULES

    lines = [l.strip() for l in existing_content.splitlines()]
    missing = []
    
    # Check .env rules
    has_env = ".env" in lines
    has_env_wildcard = ".env.*" in lines or "*.env" in lines
    has_not_example = "!.env.example" in lines
    has_not_sample = "!.env.sample" in lines
    has_not_template = "!.env.template" in lines
    has_vscode = ".vscode/" in lines or ".vscode" in lines or ".vscode/*" in lines

    additions = []
    env_additions = []
    if not has_env:
        env_additions.append(".env")
    if not has_env_wildcard:
        env_additions.append(".env.*")
    if not has_not_example:
        env_additions.append("!.env.example")
    if not has_not_sample:
        env_additions.append("!.env.sample")
    if not has_not_template:
        env_additions.append("!.env.template")

    if env_additions:
        additions.append("\n# Environment variables and local secrets")
        additions.extend(env_additions)
        missing.extend(env_additions)

    if not has_vscode:
        additions.append("\n# Local editor and workspace configuration")
        additions.append(".vscode/")
        missing.append(".vscode/")

    if not additions:
        return existing_content, True, []

    # Preserve trailing newline of original
    new_content = existing_content
    if new_content and not new_content.endswith("\n"):
        new_content += "\n"
    
    new_content += "\n".join(additions) + "\n"
    return new_content, False, missing

print("\n--- Inspecting All 95 Repositories for .vscode and Tracked Env Files ---")

for idx, r in enumerate(personal_repos, 1):
    full_name = r["full_name"]
    def_b = r.get("default_branch") or "main"
    
    # Live branch tip
    ref_res = session.get(f"https://api.github.com/repos/{full_name}/git/refs/heads/{def_b}")
    if ref_res.status_code != 200:
        print(f"[{idx}/95] Error fetching ref for {full_name}: HTTP {ref_res.status_code}")
        continue
    tip_sha = ref_res.json().get("object", {}).get("sha")

    # Live tree
    tree_res = session.get(f"https://api.github.com/repos/{full_name}/git/trees/{tip_sha}?recursive=1")
    if tree_res.status_code != 200:
        print(f"[{idx}/95] Error fetching tree for {full_name}: HTTP {tree_res.status_code}")
        continue

    tree_items = tree_res.json().get("tree", [])
    
    # 1. Find .vscode/ items
    vscode_files = [i["path"] for i in tree_items if i.get("type") == "blob" and (i["path"].startswith(".vscode/") or i["path"] == ".vscode")]
    
    # 2. Find tracked environment files
    for i in tree_items:
        if i.get("type") == "blob":
            p = i["path"]
            basename = p.split("/")[-1]
            if basename in [".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.stage", ".env.staging"] or (
                basename.startswith(".env.") and not basename.endswith((".example", ".sample", ".template"))
            ):
                tracked_env_files.append({
                    "repository": full_name,
                    "branch": def_b,
                    "commit_sha": tip_sha,
                    "path": p,
                    "size_bytes": i.get("size", 0),
                    "risk_classification": "CRITICAL (Live Secret Risk - Manual Rotation Required)"
                })
            elif basename in [".env.example", ".env.sample", ".env.template"] or basename.endswith((".example", ".sample", ".template")):
                tracked_env_files.append({
                    "repository": full_name,
                    "branch": def_b,
                    "commit_sha": tip_sha,
                    "path": p,
                    "size_bytes": i.get("size", 0),
                    "risk_classification": "LOW (Public Template - Informational Only)"
                })

    # 3. Check .gitignore
    gi_item = [i for i in tree_items if i["path"] == ".gitignore"]
    existing_gi = ""
    if gi_item:
        c_res = session.get(f"https://api.github.com/repos/{full_name}/contents/.gitignore?ref={tip_sha}")
        if c_res.status_code == 200:
            existing_gi = base64.b64decode(c_res.json().get("content", "")).decode("utf-8", errors="ignore")

    new_gi, gi_compliant, missing_rules = analyze_gitignore(existing_gi)
    
    needs_update = bool(vscode_files or not gi_compliant)
    
    repo_plans.append({
        "repository": full_name,
        "default_branch": def_b,
        "current_commit_sha": tip_sha,
        "vscode_files_to_remove": vscode_files,
        "gitignore_exists": bool(gi_item),
        "gitignore_already_compliant": gi_compliant,
        "missing_rules": missing_rules,
        "new_gitignore_content": new_gi,
        "needs_update": needs_update
    })
    
    if idx % 15 == 0 or idx == len(personal_repos):
        print(f"[{idx}/95] Evaluated {full_name} (needs_update={needs_update}, vscode_files={len(vscode_files)}, missing_rules={len(missing_rules)})")

print(f"\nInspection Complete. Found {len(tracked_env_files)} tracked environment files.")
print(f"Repositories requiring hardening commit: {sum(1 for p in repo_plans if p['needs_update'])} / {len(repo_plans)}")
print(f"Repositories already compliant: {sum(1 for p in repo_plans if not p['needs_update'])} / {len(repo_plans)}")

# Save tracked-environment-files.csv
env_csv_path = os.path.join(hardening_dir, "tracked-environment-files.csv")
with open(env_csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["repository", "branch", "commit_sha", "path", "size_bytes", "risk_classification"])
    writer.writeheader()
    writer.writerows(tracked_env_files)
print(f"Saved: {env_csv_path}")

# Save plan data for next stage
plan_json_path = os.path.join(hardening_dir, "hardening-manifest.json")
with open(plan_json_path, "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": datetime.now().isoformat(),
        "total_repositories": len(repo_plans),
        "repositories_needing_update": sum(1 for p in repo_plans if p['needs_update']),
        "repositories_already_compliant": sum(1 for p in repo_plans if not p['needs_update']),
        "tracked_environment_files_count": len(tracked_env_files),
        "plans": repo_plans
    }, f, indent=2)
print(f"Saved: {plan_json_path}")
