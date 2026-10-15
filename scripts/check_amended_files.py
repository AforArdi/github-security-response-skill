import json
import subprocess
import requests

token = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

with open(r"C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json", "r", encoding="utf-8") as f:
    repos = json.load(f)

# Repos with amended commit timestamps
target_repos = [r for r in repos if r.get("default_branch_committer_date") and (r["default_branch_committer_date"].startswith("2026-10-13") or r["default_branch_committer_date"].startswith("2026-10-14"))]

print(f"Checking files changed in amended commits for {len(target_repos)} repositories...")

summary = []
for r in target_repos:
    full_name = r["full_name"]
    sha = r["default_branch_commit_sha"]
    c_url = f"https://api.github.com/repos/{full_name}/commits/{sha}"
    res = requests.get(c_url, headers=headers)
    if res.status_code == 200:
        c_data = res.json()
        files = [f.get("filename") for f in c_data.get("files", [])]
        stats = c_data.get("stats", {})
        
        # Check for indicators in filenames
        suspicious_files = [f for f in files if any(kw in f for kw in ["api.j", "debug_api", "fa-", "fonts/", ".vscode/", "postcss.config", "next.config", "eslint.config", ".bat"])]
        
        summary.append({
            "name": r["name"],
            "language": r["language"],
            "committer_date": r["default_branch_committer_date"],
            "author_date": r["default_branch_commit_date"],
            "total_files": len(files),
            "suspicious_files": suspicious_files,
            "sample_files": files[:10]
        })
        print(f"[{r['name']}] ({r['language']}) - Total files: {len(files)}, Suspicious match: {len(suspicious_files)}")
        if suspicious_files:
            print(f"   Suspicious files: {suspicious_files[:5]}")

print("\nSummary complete.")
