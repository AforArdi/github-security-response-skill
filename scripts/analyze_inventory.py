import json
import csv
from collections import Counter, defaultdict
from datetime import datetime

with open(r"C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json", "r", encoding="utf-8") as f:
    repos = json.load(f)

with open(r"C:\Users\User\incident-investigation\recon-20261015_003000\branch-and-tag-inventory.csv", "r", encoding="utf-8") as f:
    bt_rows = list(csv.DictReader(f))

print(f"Total repositories: {len(repos)}")

# Categories
owners = Counter(r["ownership_category"] for r in repos)
print("\nOwnership Categories:")
for k, v in owners.items():
    print(f"  {k}: {v}")

vis = Counter(r["visibility"] for r in repos)
print("\nVisibility:")
for k, v in vis.items():
    print(f"  {k}: {v}")

arch = Counter(r["is_archived"] for r in repos)
print("\nArchived:")
for k, v in arch.items():
    print(f"  Archived={k}: {v}")

forks = Counter(r["is_fork"] for r in repos)
print("\nForks:")
for k, v in forks.items():
    print(f"  Fork={k}: {v}")

languages = Counter(r["language"] for r in repos)
print("\nLanguages:")
for k, v in languages.most_common(10):
    print(f"  {k}: {v}")

# Check pushed_at clustering
print("\n--- Pushed_at Analysis ---")
pushed_dates = defaultdict(list)
for r in repos:
    pushed = r["pushed_at"]
    if pushed:
        pushed_dates[pushed[:10]].append(r["name"])

for d, r_list in sorted(pushed_dates.items()):
    print(f"  Date {d}: {len(r_list)} repos pushed")

# Inspect the 2026-10-14 push spike
oct14_repos = [r for r in repos if r["pushed_at"] and r["pushed_at"].startswith("2026-10-14")]
print(f"\nTotal repos pushed on 2026-10-14: {len(oct14_repos)}")

# Check hourly/minute breakdown of Oct 14
oct14_hours = defaultdict(list)
for r in oct14_repos:
    oct14_hours[r["pushed_at"][11:16]].append(r["name"])

print("\nMinute-by-minute breakdown on 2026-10-14:")
for m, r_list in sorted(oct14_hours.items()):
    print(f"  {m} UTC: {len(r_list)} repos")

# Committer date discrepancies in branch inventory
print("\n--- Committer vs Author Date Discrepancies ---")
discrepancies = []
for b in bt_rows:
    if b["ref_type"] == "branch":
        ad = b["author_date"]
        cd = b["committer_date"]
        if ad and cd and ad[:10] != cd[:10]:
            discrepancies.append(b)

print(f"Branches with Author vs Committer Date Discrepancies (Amended/Rebased): {len(discrepancies)}")
for d in discrepancies[:15]:
    print(f"  Repo: {d['repository_full_name']} | Branch: {d['ref_name']} | Author: {d['author_date']} | Committer: {d['committer_date']} | Msg: {d['commit_message']}")

# Search for SureSale repos
print("\n--- SureSale Repositories ---")
suresale_repos = [r for r in repos if "suresale" in r["name"].lower() or "suresale" in r["description"].lower()]
for sr in suresale_repos:
    print(f"  Name: {sr['full_name']} | Pushed: {sr['pushed_at']} | Committer Date: {sr['default_branch_committer_date']}")
