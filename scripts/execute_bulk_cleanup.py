import os
import sys
import json
import csv
import time
import subprocess
from datetime import datetime
import requests

def get_token():
    return subprocess.check_output(["gh", "auth", "token"]).decode().strip()

def main():
    token = get_token()
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    })

    # Dedicated Phase 3 report directory
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    cleanup_dir = rf"C:\Users\User\incident-investigation\cleanup-{timestamp_str}"
    os.makedirs(cleanup_dir, exist_ok=True)
    print(f"Created Phase 3 cleanup directory: {cleanup_dir}")

    p2_dir = r"C:\Users\User\incident-investigation\remediation-20261015_154516"

    # Load Phase 2 manifest
    manifest_path = os.path.join(p2_dir, "remediation-manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Save reconciled manifest
    reconciled_manifest_path = os.path.join(cleanup_dir, "reconciled-remediation-manifest.json")
    with open(reconciled_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Group actions by repository
    repos_actions = {}
    for act in manifest:
        repo = act["repository"]
        if repo not in repos_actions:
            repos_actions[repo] = []
        repos_actions[repo].append(act)

    print(f"Loaded {len(repos_actions)} repositories covering {len(manifest)} reconciled actions.")

    # Load findings for expected parent SHAs
    findings_path = os.path.join(p2_dir, "repository-findings.csv")
    with open(findings_path, "r", encoding="utf-8") as f:
        findings = list(csv.DictReader(f))
    findings_by_repo = {r["repository"]: r for r in findings}

    # Initial rate limit check
    rl_init = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
    print(f"Initial Rate Limit: {rl_init.get('remaining')}/{rl_init.get('limit')} (Reset: {rl_init.get('reset')})")

    execution_records = []
    verification_records = []
    checkpoint_file = os.path.join(cleanup_dir, "cleanup-checkpoint.json")

    completed_repos = 0
    skipped_repos = 0
    failed_repos = 0

    repo_list = sorted(repos_actions.keys())
    total_repos = len(repo_list)

    print(f"\n==================================================")
    print(f"Starting verified atomic remediation across {total_repos} repositories...")
    print(f"==================================================\n")

    for idx, repo_full_name in enumerate(repo_list, 1):
        actions = repos_actions[repo_full_name]
        f_row = findings_by_repo.get(repo_full_name, {})
        default_branch = f_row.get("default_branch") or actions[0].get("default_branch") or "main"
        expected_parent_sha = f_row.get("commit_sha")

        print(f"[{idx}/{total_repos}] Remediating {repo_full_name} (branch: {default_branch})...")

        # Periodic rate limit check
        if idx % 10 == 0:
            rl_curr = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
            rem = rl_curr.get("remaining", 0)
            print(f"   [Rate Limit Quota: {rem}/{rl_curr.get('limit')}]")
            if rem < 500:
                print(f"CRITICAL: Rate limit quota nearing 10% floor ({rem} remaining). Halting gracefully.")
                break

        # 1. Pre-modification live ref check (compare-and-swap guard)
        ref_url = f"https://api.github.com/repos/{repo_full_name}/git/ref/heads/{default_branch}"
        ref_res = session.get(ref_url)
        if ref_res.status_code != 200:
            err = f"Failed to get live branch ref: HTTP {ref_res.status_code}"
            print(f"   [-] SKIPPED {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "SKIPPED",
                "previous_sha": expected_parent_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": err
            })
            skipped_repos += 1
            continue

        live_commit_sha = ref_res.json().get("object", {}).get("sha")
        if live_commit_sha != expected_parent_sha:
            err = f"Branch tip SHA changed! Expected {expected_parent_sha}, found {live_commit_sha}"
            print(f"   [-] SKIPPED {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "SKIPPED",
                "previous_sha": live_commit_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": err
            })
            skipped_repos += 1
            continue

        # 2. Get base tree SHA from live commit
        commit_url = f"https://api.github.com/repos/{repo_full_name}/git/commits/{live_commit_sha}"
        commit_res = session.get(commit_url)
        if commit_res.status_code != 200:
            err = f"Failed to get live commit object: HTTP {commit_res.status_code}"
            print(f"   [-] ERROR {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": err
            })
            failed_repos += 1
            continue

        base_tree_sha = commit_res.json().get("tree", {}).get("sha")

        # 3. Create blobs for any MODIFY actions
        tree_entries = []
        blob_creation_failed = False
        for act in actions:
            p = act["path"]
            if act["action"] == "DELETE":
                tree_entries.append({
                    "path": p,
                    "mode": "100644",
                    "type": "blob",
                    "sha": None
                })
            elif act["action"] == "MODIFY":
                p_rel = act.get("clean_patch_file")
                patch_full_path = os.path.join(p2_dir, p_rel)
                with open(patch_full_path, "r", encoding="utf-8") as pf:
                    patch_content = pf.read()

                blob_res = session.post(f"https://api.github.com/repos/{repo_full_name}/git/blobs", json={
                    "content": patch_content,
                    "encoding": "utf-8"
                })
                if blob_res.status_code not in [200, 201]:
                    err = f"Failed to create blob for {p}: HTTP {blob_res.status_code}"
                    print(f"   [-] ERROR {repo_full_name}: {err}")
                    blob_creation_failed = True
                    break
                blob_sha = blob_res.json().get("sha")
                tree_entries.append({
                    "path": p,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha
                })

        if blob_creation_failed:
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": "Blob creation failed"
            })
            failed_repos += 1
            continue

        # 4. Create new clean tree
        tree_url = f"https://api.github.com/repos/{repo_full_name}/git/trees"
        tree_res = session.post(tree_url, json={
            "base_tree": base_tree_sha,
            "tree": tree_entries
        })
        if tree_res.status_code not in [200, 201]:
            err = f"Failed to create clean git tree: HTTP {tree_res.status_code} ({tree_res.text[:100]})"
            print(f"   [-] ERROR {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": err
            })
            failed_repos += 1
            continue

        new_tree_sha = tree_res.json().get("sha")

        # 5. Create atomic remediation commit
        new_commit_res = session.post(f"https://api.github.com/repos/{repo_full_name}/git/commits", json={
            "message": "security: remove confirmed incident payloads",
            "tree": new_tree_sha,
            "parents": [live_commit_sha]
        })
        if new_commit_res.status_code not in [200, 201]:
            err = f"Failed to create git commit: HTTP {new_commit_res.status_code}"
            print(f"   [-] ERROR {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "remediation_sha": None,
                "actions_count": len(actions),
                "error": err
            })
            failed_repos += 1
            continue

        new_commit_sha = new_commit_res.json().get("sha")
        commit_html_url = f"https://github.com/{repo_full_name}/commit/{new_commit_sha}"

        # 6. Update branch ref with compare-and-swap
        patch_ref_res = session.patch(ref_url, json={
            "sha": new_commit_sha,
            "force": False
        })
        if patch_ref_res.status_code != 200:
            err = f"Failed to update branch ref: HTTP {patch_ref_res.status_code}"
            print(f"   [-] ERROR {repo_full_name}: {err}")
            execution_records.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "remediation_sha": new_commit_sha,
                "actions_count": len(actions),
                "error": err
            })
            failed_repos += 1
            continue

        # 7. Post-commit verification (Section 5)
        # Check new tree contains no targeted malicious paths
        post_tree_res = session.get(f"https://api.github.com/repos/{repo_full_name}/git/trees/{new_commit_sha}?recursive=1")
        post_tree_items = post_tree_res.json().get("tree", []) if post_tree_res.status_code == 200 else []
        remaining_paths = [item["path"] for item in post_tree_items if item.get("type") == "blob"]

        deleted_paths = [a["path"] for a in actions if a["action"] == "DELETE"]
        residual_deleted = [p for p in deleted_paths if p in remaining_paths]

        # Verify modified files exist
        modified_paths = [a["path"] for a in actions if a["action"] == "MODIFY"]
        missing_modified = [p for p in modified_paths if p not in remaining_paths]

        # Confirm branch tip equals new_commit_sha
        check_ref = session.get(ref_url).json().get("object", {}).get("sha")
        tip_verified = (check_ref == new_commit_sha)

        verification_status = "VERIFIED CLEAN" if (not residual_deleted and not missing_modified and tip_verified) else "VERIFICATION WARNING"

        execution_records.append({
            "repository": repo_full_name,
            "default_branch": default_branch,
            "status": "SUCCESS",
            "previous_sha": live_commit_sha,
            "remediation_sha": new_commit_sha,
            "commit_url": commit_html_url,
            "actions_count": len(actions),
            "deletions_count": len(deleted_paths),
            "modifications_count": len(modified_paths),
            "verification_status": verification_status,
            "error": ""
        })

        verification_records.append({
            "repository": repo_full_name,
            "remediation_sha": new_commit_sha,
            "expected_parent": live_commit_sha,
            "parent_verified": True,
            "branch_tip_verified": tip_verified,
            "residual_deleted_paths": "|".join(residual_deleted),
            "missing_modified_paths": "|".join(missing_modified),
            "overall_verification": verification_status
        })

        completed_repos += 1
        print(f"   [✓] SUCCESS: {repo_full_name} -> Commit {new_commit_sha[:8]} [{verification_status}]")

        # Save checkpoint periodically (every 10 repos or on final)
        if idx % 10 == 0 or idx == total_repos:
            ckpt_data = {
                "timestamp": datetime.now().isoformat(),
                "total_repos": total_repos,
                "completed_repos": completed_repos,
                "skipped_repos": skipped_repos,
                "failed_repos": failed_repos,
                "last_processed": repo_full_name
            }
            with open(checkpoint_file, "w", encoding="utf-8") as cf:
                json.dump(ckpt_data, cf, indent=2)

        # Gentle throttle to avoid secondary rate limits
        time.sleep(0.75)

    # Final rate limit check
    rl_end = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
    final_remaining = rl_end.get("remaining")
    print(f"\nExecution Complete. Final rate limit: {final_remaining}/{rl_end.get('limit')}")
    print(f"Results: Completed={completed_repos}, Skipped={skipped_repos}, Failed={failed_repos}")

    # Write remediation-execution-log.csv
    log_csv_path = os.path.join(cleanup_dir, "remediation-execution-log.csv")
    with open(log_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "repository", "default_branch", "status", "previous_sha", "remediation_sha",
            "commit_url", "actions_count", "deletions_count", "modifications_count",
            "verification_status", "error"
        ], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(execution_records)
    print(f"Saved: {log_csv_path}")

    # Write post-remediation-verification.csv
    veri_csv_path = os.path.join(cleanup_dir, "post-remediation-verification.csv")
    with open(veri_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "repository", "remediation_sha", "expected_parent", "parent_verified",
            "branch_tip_verified", "residual_deleted_paths", "missing_modified_paths",
            "overall_verification"
        ])
        writer.writeheader()
        writer.writerows(verification_records)
    print(f"Saved: {veri_csv_path}")

    return cleanup_dir, completed_repos, skipped_repos, failed_repos, final_remaining

if __name__ == "__main__":
    main()
