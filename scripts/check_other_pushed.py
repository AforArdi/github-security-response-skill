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

# Repos pushed on Oct 14 but whose default branch committer date was NOT Oct 2026
other_pushed = [r for r in repos if r.get("pushed_at", "").startswith("2026-10-14") and not (r.get("default_branch_committer_date") or "").startswith("2026-10")]

print(f"Total repos pushed on Oct 14 without Oct committer date on default branch: {len(other_pushed)}")

# Sample 8 diverse repos from this group
sample_repos = other_pushed[:8]

for r in sample_repos:
    full_name = r["full_name"]
    print(f"\n--- Checking {full_name} ({r['language']}) ---")
    print(f"Pushed at: {r['pushed_at']} | Default branch: {r['default_branch']}")
    
    # Check commits (last 3)
    c_res = requests.get(f"https://api.github.com/repos/{full_name}/commits?per_page=3", headers=headers)
    if c_res.status_code == 200:
        c_list = c_res.json()
        for c in c_list:
            sha = c["sha"][:8]
            c_msg = c["commit"]["message"].split("\n")[0]
            c_auth = c["commit"]["author"]["date"]
            c_comm = c["commit"]["committer"]["date"]
            print(f"  Commit {sha}: auth={c_auth} comm={c_comm} msg={c_msg}")
    
    # Check tree of default branch for suspicious files
    tree_res = requests.get(f"https://api.github.com/repos/{full_name}/git/trees/{r['default_branch']}?recursive=1", headers=headers)
    if tree_res.status_code == 200:
        tree_items = tree_res.json().get("tree", [])
        sus = [i["path"] for i in tree_items if any(k in i["path"] for k in ["api.j", "debug_api", "fa-", "fonts/", ".vscode/", "postcss.config", "next.config", "eslint.config", ".bat"])]
        print(f"  Tree items total: {len(tree_items)}, suspicious matches: {len(sus)}")
        if sus:
            print(f"  Suspicious items in tree: {sus[:5]}")
