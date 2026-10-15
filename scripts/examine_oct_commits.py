import json
import csv

with open(r"C:\Users\User\incident-investigation\recon-20261015_003000\branch-and-tag-inventory.csv", "r", encoding="utf-8") as f:
    bt_rows = list(csv.DictReader(f))

with open(r"C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json", "r", encoding="utf-8") as f:
    repos = json.load(f)

# Find all branches where committer date is in Oct 2026
oct_branches = [b for b in bt_rows if b.get("committer_date") and b["committer_date"].startswith("2026-10")]
print(f"Total branches with committer_date in Oct 2026: {len(oct_branches)}")

# Find all repos where default branch commit was created or committed in Oct 2026
oct_repos = [r for r in repos if (r.get("default_branch_committer_date") and r["default_branch_committer_date"].startswith("2026-10")) or (r.get("default_branch_commit_date") and r["default_branch_commit_date"].startswith("2026-10"))]
print(f"Total repos with default branch commit in Oct 2026: {len(oct_repos)}")

for r in oct_repos:
    print(f"{r['name']} | lang: {r['language']} | committer: {r['default_branch_committer_date']} | author: {r['default_branch_commit_date']} | msg: {r['default_branch_commit_message']}")

# Find SureSale variations
print("\nChecking for SureSale under different names:")
for r in repos:
    if "sure" in r["name"].lower() or "sale" in r["name"].lower():
        print(f"Found match: {r['full_name']}")
