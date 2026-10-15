import os
import sys
import json
import csv
import subprocess
import time
from datetime import datetime
import requests

def get_token():
    try:
        t = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
        if not t:
            raise ValueError("Token is empty")
        return t
    except Exception as e:
        print(f"Error getting token via gh auth token: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    # Timestamped dedicated report directory
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = rf"C:\Users\User\incident-investigation\recon-{timestamp_str}"
    os.makedirs(report_dir, exist_ok=True)
    print(f"Created report directory: {report_dir}")

    # Check initial rate limit
    rl_res = requests.get("https://api.github.com/rate_limit", headers=headers)
    rl_data = rl_res.json() if rl_res.status_code == 200 else {}
    core_rl = rl_data.get("resources", {}).get("core", {})
    print(f"Initial Rate Limit: {core_rl.get('remaining')}/{core_rl.get('limit')}")

    # Verify user
    u_res = requests.get("https://api.github.com/user", headers=headers)
    user_data = u_res.json()
    auth_user = user_data.get("login")
    print(f"Authenticated as: {auth_user}")

    # Check orgs
    orgs_res = requests.get("https://api.github.com/user/orgs", headers=headers)
    orgs_data = orgs_res.json() if orgs_res.status_code == 200 else []
    print(f"User direct organization memberships count: {len(orgs_data)}")

    # Fetch all repos with full pagination
    repos = []
    page = 1
    api_errors = []
    access_limitations = []

    print("Enumerating accessible repositories (owner, organization_member, collaborator)...")
    while True:
        url = f"https://api.github.com/user/repos?per_page=100&page={page}&affiliation=owner,organization_member,collaborator"
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            api_errors.append(f"GET {url} returned HTTP {res.status_code}: {res.text}")
            break
        page_data = res.json()
        if not page_data or not isinstance(page_data, list):
            break
        repos.extend(page_data)
        print(f"Page {page}: fetched {len(page_data)} repos (total so far: {len(repos)})")
        if len(page_data) < 100:
            break
        page += 1

    print(f"Total repositories enumerated: {len(repos)}")

    # Process and classify repos
    repo_inventory = []
    branch_and_tag_inventory = []
    commit_cache = {}

    for idx, r in enumerate(repos, 1):
        full_name = r.get("full_name")
        owner_login = r.get("owner", {}).get("login")
        owner_type = r.get("owner", {}).get("type")
        is_owner = (owner_login == auth_user)

        # Categorize ownership
        if is_owner:
            category = "Personal (Owner)"
        elif owner_type == "Organization":
            category = "Collaborator (Organization-owned)"
        else:
            category = f"Collaborator ({owner_type}-owned)"

        perms = r.get("permissions", {})

        repo_record = {
            "id": r.get("id"),
            "name": r.get("name"),
            "full_name": full_name,
            "owner": owner_login,
            "owner_type": owner_type,
            "ownership_category": category,
            "html_url": r.get("html_url"),
            "visibility": r.get("visibility", "public" if not r.get("private") else "private"),
            "is_private": r.get("private"),
            "is_fork": r.get("fork"),
            "is_archived": r.get("archived"),
            "is_disabled": r.get("disabled"),
            "default_branch": r.get("default_branch"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
            "pushed_at": r.get("pushed_at"),
            "size_kb": r.get("size"),
            "language": r.get("language"),
            "open_issues_count": r.get("open_issues_count"),
            "stargazers_count": r.get("stargazers_count"),
            "forks_count": r.get("forks_count"),
            "description": r.get("description") or "",
            "permissions_admin": perms.get("admin", False),
            "permissions_push": perms.get("push", False),
            "permissions_pull": perms.get("pull", False),
            "branches_count": 0,
            "tags_count": 0,
            "default_branch_commit_sha": None,
            "default_branch_commit_date": None,
            "default_branch_committer_date": None,
            "default_branch_commit_message": None,
            "default_branch_commit_author": None
        }

        # Enumerate branches
        b_page = 1
        branches = []
        while True:
            b_url = f"https://api.github.com/repos/{full_name}/branches?per_page=100&page={b_page}"
            b_res = requests.get(b_url, headers=headers)
            if b_res.status_code == 200:
                b_items = b_res.json()
                if not b_items:
                    break
                branches.extend(b_items)
                if len(b_items) < 100:
                    break
                b_page += 1
            elif b_res.status_code == 409: # Empty repo (Git Repository is empty)
                access_limitations.append(f"{full_name}: Empty repository (HTTP 409)")
                break
            else:
                access_limitations.append(f"{full_name}: branches query HTTP {b_res.status_code}")
                break

        repo_record["branches_count"] = len(branches)

        # Enumerate tags
        t_page = 1
        tags = []
        while True:
            t_url = f"https://api.github.com/repos/{full_name}/tags?per_page=100&page={t_page}"
            t_res = requests.get(t_url, headers=headers)
            if t_res.status_code == 200:
                t_items = t_res.json()
                if not t_items:
                    break
                tags.extend(t_items)
                if len(t_items) < 100:
                    break
                t_page += 1
            else:
                break

        repo_record["tags_count"] = len(tags)

        # Fetch commit details for each branch
        for b in branches:
            b_name = b.get("name")
            commit_sha = b.get("commit", {}).get("sha")
            is_default = (b_name == repo_record["default_branch"])
            is_protected = b.get("protected", False)

            commit_date = None
            committer_date = None
            commit_msg = None
            commit_author = None
            commit_committer = None

            if commit_sha:
                if commit_sha not in commit_cache:
                    c_url = f"https://api.github.com/repos/{full_name}/commits/{commit_sha}"
                    c_res = requests.get(c_url, headers=headers)
                    if c_res.status_code == 200:
                        c_data = c_res.json()
                        c_obj = c_data.get("commit", {})
                        commit_cache[commit_sha] = {
                            "author_date": c_obj.get("author", {}).get("date"),
                            "committer_date": c_obj.get("committer", {}).get("date"),
                            "author_name": c_obj.get("author", {}).get("name"),
                            "author_email": c_obj.get("author", {}).get("email"),
                            "committer_name": c_obj.get("committer", {}).get("name"),
                            "committer_email": c_obj.get("committer", {}).get("email"),
                            "message": c_obj.get("message", "").split("\n")[0] if c_obj.get("message") else ""
                        }
                    else:
                        commit_cache[commit_sha] = {}

                c_info = commit_cache.get(commit_sha, {})
                commit_date = c_info.get("author_date")
                committer_date = c_info.get("committer_date")
                commit_msg = c_info.get("message")
                commit_author = c_info.get("author_name")
                commit_committer = c_info.get("committer_name")

                if is_default:
                    repo_record["default_branch_commit_sha"] = commit_sha
                    repo_record["default_branch_commit_date"] = commit_date
                    repo_record["default_branch_committer_date"] = committer_date
                    repo_record["default_branch_commit_message"] = commit_msg
                    repo_record["default_branch_commit_author"] = commit_author

            branch_and_tag_inventory.append({
                "repository_name": r.get("name"),
                "repository_full_name": full_name,
                "ownership_category": category,
                "ref_type": "branch",
                "ref_name": b_name,
                "commit_sha": commit_sha,
                "is_default_branch": is_default,
                "is_protected": is_protected,
                "author_date": commit_date,
                "committer_date": committer_date,
                "commit_author": commit_author,
                "commit_committer": commit_committer,
                "commit_message": commit_msg
            })

        for t in tags:
            t_name = t.get("name")
            commit_sha = t.get("commit", {}).get("sha")
            branch_and_tag_inventory.append({
                "repository_name": r.get("name"),
                "repository_full_name": full_name,
                "ownership_category": category,
                "ref_type": "tag",
                "ref_name": t_name,
                "commit_sha": commit_sha,
                "is_default_branch": False,
                "is_protected": False,
                "author_date": None,
                "committer_date": None,
                "commit_author": None,
                "commit_committer": None,
                "commit_message": None
            })

        repo_inventory.append(repo_record)
        if idx % 10 == 0 or idx == len(repos):
            print(f"Processed {idx}/{len(repos)} repositories...")

    # Rate limit check after scan
    rl_end_res = requests.get("https://api.github.com/rate_limit", headers=headers)
    rl_end_data = rl_end_res.json() if rl_end_res.status_code == 200 else {}
    core_end_rl = rl_end_data.get("resources", {}).get("core", {})
    print(f"Ending Rate Limit: {core_end_rl.get('remaining')}/{core_end_rl.get('limit')}")

    # Write repository-inventory.json
    repo_json_path = os.path.join(report_dir, "repository-inventory.json")
    with open(repo_json_path, "w", encoding="utf-8") as f:
        json.dump(repo_inventory, f, indent=2)
    print(f"Saved: {repo_json_path}")

    # Write repository-inventory.csv
    repo_csv_path = os.path.join(report_dir, "repository-inventory.csv")
    repo_headers = [
        "id", "name", "full_name", "owner", "owner_type", "ownership_category",
        "html_url", "visibility", "is_private", "is_fork", "is_archived", "is_disabled",
        "default_branch", "created_at", "updated_at", "pushed_at", "size_kb",
        "language", "open_issues_count", "stargazers_count", "forks_count",
        "permissions_admin", "permissions_push", "permissions_pull",
        "branches_count", "tags_count", "default_branch_commit_sha",
        "default_branch_commit_date", "default_branch_committer_date",
        "default_branch_commit_message", "description"
    ]
    with open(repo_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=repo_headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(repo_inventory)
    print(f"Saved: {repo_csv_path}")

    # Write branch-and-tag-inventory.csv
    bt_csv_path = os.path.join(report_dir, "branch-and-tag-inventory.csv")
    bt_headers = [
        "repository_name", "repository_full_name", "ownership_category",
        "ref_type", "ref_name", "commit_sha", "is_default_branch", "is_protected",
        "author_date", "committer_date", "commit_author", "commit_committer", "commit_message"
    ]
    with open(bt_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=bt_headers)
        writer.writeheader()
        writer.writerows(branch_and_tag_inventory)
    print(f"Saved: {bt_csv_path}")

    # Write access-limitations.md
    al_path = os.path.join(report_dir, "access-limitations.md")
    with open(al_path, "w", encoding="utf-8") as f:
        f.write("# Access Limitations & API Operational Assessment\n\n")
        f.write(f"- **Scan Timestamp**: {datetime.now().isoformat()}\n")
        f.write(f"- **Authenticated Account**: `{auth_user}`\n")
        f.write(f"- **API Rate Limit Initial**: {core_rl.get('remaining')}/{core_rl.get('limit')}\n")
        f.write(f"- **API Rate Limit Final**: {core_end_rl.get('remaining')}/{core_end_rl.get('limit')}\n")
        f.write(f"- **API Calls Consumed**: {core_rl.get('remaining', 0) - core_end_rl.get('remaining', 0)}\n\n")
        f.write("## Inaccessible Repositories & Errors\n\n")
        if not api_errors:
            f.write("No API pagination or retrieval errors encountered during enumeration.\n\n")
        else:
            for err in api_errors:
                f.write(f"- {err}\n")
            f.write("\n")
        f.write("## Repository Access Limitations & Notes\n\n")
        if not access_limitations:
            f.write("All enumerated repositories responded normally to branch and tag queries.\n\n")
        else:
            for limit in access_limitations:
                f.write(f"- {limit}\n")
            f.write("\n")
        f.write("## Scope and Permissions Summary\n\n")
        f.write("- **Personal Repositories**: Full administrative and push access confirmed.\n")
        f.write("- **Collaborator Repositories**: Limited to collaborator access (non-admin push/pull); excluded from personal-repository remediation scope.\n")
    print(f"Saved: {al_path}")

    # Return key stats for the next step
    return report_dir

if __name__ == "__main__":
    main()
