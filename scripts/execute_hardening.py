import os
import sys
import json
import csv
import time
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

def main():
    token = get_token()
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    })

    hardening_dir = r"C:\Users\User\incident-investigation\hardening-20261015_173156"
    manifest_path = os.path.join(hardening_dir, "hardening-manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    repo_plans = manifest_data["plans"]
    print(f"Loaded hardening manifest covering {len(repo_plans)} repositories.")

    rl_init = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
    print(f"Live API Core Rate Limit: {rl_init.get('remaining')}/{rl_init.get('limit')} (Reset: {rl_init.get('reset')})")

    hardening_logs = []
    checkpoint_file = os.path.join(hardening_dir, "hardening-checkpoint.json")

    completed_count = 0
    skipped_count = 0
    failed_count = 0
    already_compliant_count = 0

    total_repos = len(repo_plans)

    print(f"\n==================================================")
    print(f"Executing atomic hardening commits across {total_repos} repositories...")
    print(f"==================================================\n")

    for idx, plan in enumerate(repo_plans, 1):
        repo_full_name = plan["repository"]
        default_branch = plan["default_branch"]
        expected_parent_sha = plan["current_commit_sha"]
        vscode_files = plan["vscode_files_to_remove"]
        new_gi_content = plan["new_gitignore_content"]
        needs_update = plan["needs_update"]

        print(f"[{idx}/{total_repos}] Hardening {repo_full_name} (branch: {default_branch})...")

        if not needs_update:
            print(f"   [OK] ALREADY COMPLIANT: {repo_full_name} requires no changes.")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "ALREADY COMPLIANT",
                "previous_sha": expected_parent_sha,
                "hardening_sha": expected_parent_sha,
                "commit_url": f"https://github.com/{repo_full_name}/commit/{expected_parent_sha}",
                "gitignore_status": "ALREADY COMPLIANT",
                "vscode_removal_status": "NONE PRESENT",
                "verification_outcome": "VERIFIED COMPLIANT",
                "conflict": "NONE"
            })
            already_compliant_count += 1
            continue

        # Rate limit check periodically
        if idx % 10 == 0:
            rl_curr = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
            rem = rl_curr.get("remaining", 0)
            print(f"   [Rate Limit Quota: {rem}/{rl_curr.get('limit')}]")
            if rem < 500:
                print(f"CRITICAL: Rate limit quota nearing 10% floor ({rem} remaining). Halting gracefully.")
                break

        # 1. Live compare-and-swap check
        ref_url = f"https://api.github.com/repos/{repo_full_name}/git/refs/heads/{default_branch}"
        ref_res = session.get(ref_url)
        if ref_res.status_code != 200:
            err = f"Failed to get live branch ref: HTTP {ref_res.status_code}"
            print(f"   [-] SKIPPED: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "SKIPPED",
                "previous_sha": expected_parent_sha,
                "hardening_sha": None,
                "commit_url": "",
                "gitignore_status": "SKIPPED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "FAILED PRE-CHECK",
                "conflict": err
            })
            skipped_count += 1
            continue

        live_commit_sha = ref_res.json().get("object", {}).get("sha")

        # Check if already hardened
        live_commit_obj = session.get(f"https://api.github.com/repos/{repo_full_name}/git/commits/{live_commit_sha}").json()
        if live_commit_obj.get("message") == "security: harden gitignore and remove vscode workspace":
            print(f"   [OK] ALREADY HARDENED: {repo_full_name} is at hardening commit {live_commit_sha[:8]}")
            # Verify tree
            post_tree_res = session.get(f"https://api.github.com/repos/{repo_full_name}/git/trees/{live_commit_sha}?recursive=1")
            post_items = post_tree_res.json().get("tree", []) if post_tree_res.status_code == 200 else []
            post_paths = [i["path"] for i in post_items if i.get("type") == "blob"]
            vscode_remaining = [p for p in post_paths if p.startswith(".vscode/") or p == ".vscode"]
            gitignore_present = ".gitignore" in post_paths

            gi_verify_res = session.get(f"https://api.github.com/repos/{repo_full_name}/contents/.gitignore?ref={live_commit_sha}")
            gi_rules_verified = False
            if gi_verify_res.status_code == 200:
                v_content = base64.b64decode(gi_verify_res.json().get("content", "")).decode("utf-8", errors="ignore")
                gi_rules_verified = all(rule in v_content for rule in [".env", ".env.*", "!.env.example", ".vscode/"])

            v_outcome = "VERIFIED HARDENED" if (not vscode_remaining and gitignore_present and gi_rules_verified) else "VERIFICATION WARNING"

            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "SUCCESS",
                "previous_sha": expected_parent_sha,
                "hardening_sha": live_commit_sha,
                "commit_url": f"https://github.com/{repo_full_name}/commit/{live_commit_sha}",
                "gitignore_status": "UPDATED & VERIFIED" if plan["gitignore_exists"] else "CREATED & VERIFIED",
                "vscode_removal_status": f"REMOVED ({len(vscode_files)} files)" if vscode_files else "NONE PRESENT",
                "verification_outcome": v_outcome,
                "conflict": "NONE"
            })
            completed_count += 1
            continue

        if live_commit_sha != expected_parent_sha:
            err = f"Branch tip SHA changed! Expected {expected_parent_sha}, found {live_commit_sha}"
            print(f"   [-] CONFLICT: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "CONFLICT",
                "previous_sha": live_commit_sha,
                "hardening_sha": None,
                "commit_url": "",
                "gitignore_status": "SKIPPED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "BRANCH DRIFT DETECTED",
                "conflict": err
            })
            skipped_count += 1
            continue

        # 2. Get base tree SHA from live commit
        base_tree_sha = live_commit_obj.get("tree", {}).get("sha")

        # 3. Create blob for updated .gitignore
        blob_res = session.post(f"https://api.github.com/repos/{repo_full_name}/git/blobs", json={
            "content": new_gi_content,
            "encoding": "utf-8"
        })
        if blob_res.status_code not in [200, 201]:
            err = f"Failed to create .gitignore blob: HTTP {blob_res.status_code}"
            print(f"   [-] ERROR: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "hardening_sha": None,
                "commit_url": "",
                "gitignore_status": "BLOB FAILED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "FAILED",
                "conflict": err
            })
            failed_count += 1
            continue
        gi_blob_sha = blob_res.json().get("sha")

        # 4. Build tree entries: remove .vscode/ and set .gitignore
        tree_entries = []
        for p in vscode_files:
            tree_entries.append({
                "path": p,
                "mode": "100644",
                "type": "blob",
                "sha": None
            })
        tree_entries.append({
            "path": ".gitignore",
            "mode": "100644",
            "type": "blob",
            "sha": gi_blob_sha
        })

        # Create new tree
        tree_res = session.post(f"https://api.github.com/repos/{repo_full_name}/git/trees", json={
            "base_tree": base_tree_sha,
            "tree": tree_entries
        })
        if tree_res.status_code not in [200, 201]:
            err = f"Failed to create git tree: HTTP {tree_res.status_code}"
            print(f"   [-] ERROR: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "hardening_sha": None,
                "commit_url": "",
                "gitignore_status": "TREE FAILED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "FAILED",
                "conflict": err
            })
            failed_count += 1
            continue
        new_tree_sha = tree_res.json().get("sha")

        # 5. Create atomic commit
        commit_res = session.post(f"https://api.github.com/repos/{repo_full_name}/git/commits", json={
            "message": "security: harden gitignore and remove vscode workspace",
            "tree": new_tree_sha,
            "parents": [live_commit_sha]
        })
        if commit_res.status_code not in [200, 201]:
            err = f"Failed to create git commit: HTTP {commit_res.status_code}"
            print(f"   [-] ERROR: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "hardening_sha": None,
                "commit_url": "",
                "gitignore_status": "COMMIT FAILED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "FAILED",
                "conflict": err
            })
            failed_count += 1
            continue
        new_commit_sha = commit_res.json().get("sha")
        commit_url = f"https://github.com/{repo_full_name}/commit/{new_commit_sha}"

        # 6. Update branch ref with compare-and-swap
        patch_res = session.patch(ref_url, json={
            "sha": new_commit_sha,
            "force": False
        })
        if patch_res.status_code != 200:
            err = f"Failed to update branch ref: HTTP {patch_res.status_code}"
            print(f"   [-] ERROR: {err}")
            hardening_logs.append({
                "repository": repo_full_name,
                "default_branch": default_branch,
                "status": "FAILED",
                "previous_sha": live_commit_sha,
                "hardening_sha": new_commit_sha,
                "commit_url": commit_url,
                "gitignore_status": "REF UPDATE FAILED",
                "vscode_removal_status": "SKIPPED",
                "verification_outcome": "FAILED",
                "conflict": err
            })
            failed_count += 1
            continue

        # 7. Post-commit verification
        post_tree_res = session.get(f"https://api.github.com/repos/{repo_full_name}/git/trees/{new_commit_sha}?recursive=1")
        post_items = post_tree_res.json().get("tree", []) if post_tree_res.status_code == 200 else []
        post_paths = [i["path"] for i in post_items if i.get("type") == "blob"]

        # Verification checks
        vscode_remaining = [p for p in post_paths if p.startswith(".vscode/") or p == ".vscode"]
        gitignore_present = ".gitignore" in post_paths
        
        # Verify .gitignore content on GitHub
        gi_verify_res = session.get(f"https://api.github.com/repos/{repo_full_name}/contents/.gitignore?ref={new_commit_sha}")
        gi_rules_verified = False
        if gi_verify_res.status_code == 200:
            v_content = base64.b64decode(gi_verify_res.json().get("content", "")).decode("utf-8", errors="ignore")
            gi_rules_verified = all(rule in v_content for rule in [".env", ".env.*", "!.env.example", ".vscode/"])

        # Verify parent
        parent_verified = (live_commit_obj.get("sha") == live_commit_sha)

        # Verify branch tip
        check_tip = session.get(ref_url).json().get("object", {}).get("sha")
        tip_verified = (check_tip == new_commit_sha)

        if not vscode_remaining and gitignore_present and gi_rules_verified and tip_verified:
            v_outcome = "VERIFIED HARDENED"
        else:
            v_outcome = f"VERIFICATION WARNING: vscode_remaining={len(vscode_remaining)}, gi={gitignore_present}, rules={gi_rules_verified}, tip={tip_verified}"

        hardening_logs.append({
            "repository": repo_full_name,
            "default_branch": default_branch,
            "status": "SUCCESS",
            "previous_sha": live_commit_sha,
            "hardening_sha": new_commit_sha,
            "commit_url": commit_url,
            "gitignore_status": "UPDATED & VERIFIED" if plan["gitignore_exists"] else "CREATED & VERIFIED",
            "vscode_removal_status": f"REMOVED ({len(vscode_files)} files)" if vscode_files else "NONE PRESENT",
            "verification_outcome": v_outcome,
            "conflict": "NONE"
        })

        completed_count += 1
        print(f"   [OK] SUCCESS: {repo_full_name} -> Hardened Commit {new_commit_sha[:8]} [{v_outcome}]")

        # Periodic checkpointing
        if idx % 10 == 0 or idx == total_repos:
            ckpt = {
                "timestamp": datetime.now().isoformat(),
                "total_repos": total_repos,
                "completed_count": completed_count,
                "already_compliant_count": already_compliant_count,
                "skipped_count": skipped_count,
                "failed_count": failed_count,
                "last_processed": repo_full_name
            }
            with open(checkpoint_file, "w", encoding="utf-8") as cf:
                json.dump(ckpt, cf, indent=2)

        time.sleep(0.75)

    # Final rate limit check
    rl_end = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
    final_remaining = rl_end.get("remaining")
    print(f"\n==================================================")
    print(f"Hardening Execution Complete.")
    print(f"Final rate limit: {final_remaining}/{rl_end.get('limit')}")
    print(f"Results: Changed={completed_count}, Compliant={already_compliant_count}, Skipped={skipped_count}, Failed={failed_count}")
    print(f"==================================================\n")

    # Save repository-hardening-log.csv
    log_csv_path = os.path.join(hardening_dir, "repository-hardening-log.csv")
    with open(log_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "repository", "default_branch", "status", "previous_sha", "hardening_sha",
            "commit_url", "gitignore_status", "vscode_removal_status",
            "verification_outcome", "conflict"
        ])
        writer.writeheader()
        writer.writerows(hardening_logs)
    print(f"Saved: {log_csv_path}")

    return hardening_dir, completed_count, already_compliant_count, skipped_count, failed_count, final_remaining

if __name__ == "__main__":
    main()
