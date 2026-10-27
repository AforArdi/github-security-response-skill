import subprocess
import json
import time
import os
import sys

RULESET_PAYLOAD = {
    "name": "Require Signed Commits",
    "target": "branch",
    "enforcement": "active",
    "conditions": {
        "ref_name": {
            "include": ["~ALL"],
            "exclude": []
        }
    },
    "rules": [
        {
            "type": "required_signatures"
        }
    ]
}

def run_gh_api(endpoint, method="GET", json_body=None):
    cmd = ["gh", "api"]
    if method != "GET":
        cmd += ["--method", method]
    cmd.append(endpoint)
    
    input_data = None
    if json_body is not None:
        cmd.append("--input")
        cmd.append("-")
        input_data = json.dumps(json_body)

    res = subprocess.run(
        cmd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if res.returncode != 0:
        return None, res.stderr.strip()
    try:
        return json.loads(res.stdout), None
    except Exception as e:
        return res.stdout.strip(), None

def main():
    print("=" * 75)
    print("BULK RULESET DEPLOYMENT: REQUIRE SIGNED COMMITS (~ALL BRANCHES)")
    print("Enforcing cryptographic signature verification across all eligible repos")
    print("=" * 75)

    # 1. Verify User Identity
    user_info, err = run_gh_api("user")
    if not user_info or "login" not in user_info:
        print(f"[FATAL] Failed to authenticate user: {err}")
        sys.exit(1)
    
    login = user_info["login"]
    print(f"Authenticated as: {login}")

    # 2. Enumerate All Personally Owned Repositories with Pagination
    all_repos = []
    page = 1
    while True:
        endpoint = f"user/repos?per_page=100&page={page}&affiliation=owner"
        repos_page, err = run_gh_api(endpoint)
        if not repos_page or not isinstance(repos_page, list):
            break
        all_repos.extend(repos_page)
        if len(repos_page) < 100:
            break
        page += 1

    print(f"Total personally owned repositories retrieved: {len(all_repos)}\n")

    # Track results
    applied_count = 0
    already_exists_count = 0
    skipped_private_count = 0
    failed_count = 0

    results = []

    for idx, repo in enumerate(all_repos, 1):
        full_name = repo["full_name"]
        is_private = repo.get("private", False)

        print(f"[{idx}/{len(all_repos)}] Processing: {full_name} ...", end=" ", flush=True)

        # 3. Handle Private Repositories on Free Plan
        if is_private:
            print("SKIPPED (Private - GitHub Free plan requires Pro/Team for private rulesets)")
            skipped_private_count += 1
            results.append({
                "repo": full_name,
                "status": "SKIPPED_PRIVATE",
                "details": "Private repository on GitHub Free tier. Rulesets require GitHub Pro / Team or making repository public."
            })
            continue

        # 4. Check for Existing Ruleset
        rulesets, err = run_gh_api(f"repos/{full_name}/rulesets")
        if rulesets is None:
            print(f"ERROR checking rulesets: {err}")
            failed_count += 1
            results.append({
                "repo": full_name,
                "status": "FAILED",
                "details": f"Failed to query existing rulesets: {err}"
            })
            continue

        # Check if "Require Signed Commits" or any required_signatures rule exists
        already_has_rule = False
        if isinstance(rulesets, list):
            for rs in rulesets:
                if rs.get("name") == "Require Signed Commits":
                    already_has_rule = True
                    break

        if already_has_rule:
            print("ALREADY ACTIVE (Skipped)")
            already_exists_count += 1
            results.append({
                "repo": full_name,
                "status": "ALREADY_ACTIVE",
                "details": "Ruleset 'Require Signed Commits' is already active."
            })
            continue

        # 5. Apply Ruleset via POST
        create_res, err = run_gh_api(f"repos/{full_name}/rulesets", method="POST", json_body=RULESET_PAYLOAD)
        if create_res and isinstance(create_res, dict) and "id" in create_res:
            print(f"SUCCESS (Ruleset ID: {create_res['id']})")
            applied_count += 1
            results.append({
                "repo": full_name,
                "status": "SUCCESS",
                "ruleset_id": create_res["id"],
                "details": "Applied 'Require Signed Commits' ruleset to ~ALL branches."
            })
        else:
            print(f"FAILED ({err})")
            failed_count += 1
            results.append({
                "repo": full_name,
                "status": "FAILED",
                "details": err
            })

    # Summary Output
    print("\n" + "=" * 75)
    print("RULESET DEPLOYMENT SUMMARY")
    print("=" * 75)
    print(f"Total Repositories Evaluated : {len(all_repos)}")
    print(f"New Rulesets Applied         : {applied_count}")
    print(f"Already Active               : {already_exists_count}")
    print(f"Skipped Private Repositories : {skipped_private_count}")
    print(f"Failed                       : {failed_count}")
    print("=" * 75)

    # Save detailed JSON report
    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user": login,
        "total_repos": len(all_repos),
        "applied": applied_count,
        "already_active": already_exists_count,
        "skipped_private": skipped_private_count,
        "failed": failed_count,
        "results": results
    }

    report_path = os.path.join(os.path.dirname(__file__), "ruleset_deployment_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Detailed report saved to: {report_path}")

if __name__ == "__main__":
    main()
