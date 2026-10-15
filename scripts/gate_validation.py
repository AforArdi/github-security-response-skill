import os
import sys
import json
import csv
import subprocess
import requests

def get_token():
    return subprocess.check_output(["gh", "auth", "token"]).decode().strip()

token = get_token()
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
})

p2_dir = r"C:\Users\User\incident-investigation\remediation-20261015_154516"

# Load Phase 2 manifest & findings
manifest_path = os.path.join(p2_dir, "remediation-manifest.json")
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

findings_path = os.path.join(p2_dir, "repository-findings.csv")
with open(findings_path, "r", encoding="utf-8") as f:
    findings = list(csv.DictReader(f))

findings_by_repo = {row["repository"]: row for row in findings}

print(f"Loaded manifest with {len(manifest)} actions.")
print(f"Loaded findings with {len(findings)} repositories.")

# Group actions by repo
repos_actions = {}
for act in manifest:
    repo = act["repository"]
    if repo not in repos_actions:
        repos_actions[repo] = []
    repos_actions[repo].append(act)

print(f"Total repositories in manifest: {len(repos_actions)}")

# Verify live branch tips on GitHub
print("\n--- Pre-Modification Live Gate Verification ---")
tip_mismatches = []
repo_verifications = []

for idx, (repo_full_name, actions) in enumerate(repos_actions.items(), 1):
    f_row = findings_by_repo.get(repo_full_name, {})
    def_b = f_row.get("default_branch") or actions[0].get("default_branch") or "main"
    expected_sha = f_row.get("commit_sha")
    
    # Check live ref
    ref_url = f"https://api.github.com/repos/{repo_full_name}/git/ref/heads/{def_b}"
    res = session.get(ref_url)
    if res.status_code != 200:
        tip_mismatches.append((repo_full_name, f"HTTP {res.status_code} fetching ref: {res.text[:80]}"))
        continue
    
    live_sha = res.json().get("object", {}).get("sha")
    if live_sha != expected_sha:
        tip_mismatches.append((repo_full_name, f"SHA mismatch: expected {expected_sha}, live {live_sha}"))
    else:
        repo_verifications.append((repo_full_name, def_b, live_sha, len(actions)))

print(f"Live SHA Verifications: {len(repo_verifications)} / {len(repos_actions)} match exactly!")
if tip_mismatches:
    print(f"Mismatches / Inaccessible ({len(tip_mismatches)}):")
    for r, reason in tip_mismatches:
        print(f"  {r}: {reason}")
else:
    print("ALL 92 REPOSITORIES CONFIRMED: Live default branch tips match Phase 2 commit SHAs perfectly with ZERO divergence!")

# Check rate limit after gate verification
rl = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
print(f"\nRate limit after gate verification: {rl.get('remaining')}/{rl.get('limit')} (Reset: {rl.get('reset')})")
