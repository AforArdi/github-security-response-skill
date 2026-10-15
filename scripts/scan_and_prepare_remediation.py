import os
import sys
import json
import csv
import base64
import hashlib
import re
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

    # Dedicated timestamped output directory
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = rf"C:\Users\User\incident-investigation\remediation-{timestamp_str}"
    patches_dir = os.path.join(out_dir, "patches")
    os.makedirs(patches_dir, exist_ok=True)
    print(f"Created output directory: {out_dir}")

    # Check live rate limit
    rl_res = session.get("https://api.github.com/rate_limit")
    rl_data = rl_res.json() if rl_res.status_code == 200 else {}
    core_rl = rl_data.get("resources", {}).get("core", {})
    init_remaining = core_rl.get("remaining", 0)
    init_limit = core_rl.get("limit", 5000)
    print(f"Live API Core Rate Limit: {init_remaining}/{init_limit} (Reset: {core_rl.get('reset')})")

    if init_remaining < 500:
        print("ERROR: Rate limit remaining is below safety threshold (500). Aborting.", file=sys.stderr)
        sys.exit(1)

    # Load Phase 1 inventory
    inv_path = r"C:\Users\User\incident-investigation\recon-20261015_003000\repository-inventory.json"
    with open(inv_path, "r", encoding="utf-8") as f:
        all_repos = json.load(f)

    # Filter 95 personal repositories
    personal_repos = [r for r in all_repos if r.get("ownership_category") == "Personal (Owner)"]
    print(f"Loaded {len(personal_repos)} personal repositories for full scanning.")

    # Known signature constants
    KNOWN_TTF_HASH = "b1b7e39cd73f3d26ca4d9a7d335730f1d5c23db022b17c76248eb2475a985cea"
    KNOWN_README_HASH = "462725bd6964a784d09320e8a719d36e2f1648a0494be108b991515bb2b453a2"

    repo_findings = []
    remediation_manifest = []
    checkpoint = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_repositories": len(personal_repos),
        "completed_count": 0,
        "unfinished_repositories": [],
        "rate_limit_initial": init_remaining,
        "rate_limit_final": None,
        "quota_reset": core_rl.get("reset")
    }

    confirmed_count = 0
    suspicious_count = 0
    clean_count = 0
    incomplete_count = 0

    for idx, repo in enumerate(personal_repos, 1):
        repo_name = repo["name"]
        full_name = repo["full_name"]
        default_branch = repo.get("default_branch") or "main"

        # Check rate limit periodically
        if idx % 10 == 0:
            rl_check = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
            rem = rl_check.get("remaining", 0)
            print(f"[{idx}/{len(personal_repos)}] Rate limit check: {rem}/{rl_check.get('limit')}")
            if rem < 500:
                print(f"WARNING: Approaching rate limit floor ({rem} remaining). Stopping scan early at repo {idx}.")
                checkpoint["unfinished_repositories"] = [r["full_name"] for r in personal_repos[idx-1:]]
                break

        # Fetch tree of default branch
        tree_url = f"https://api.github.com/repos/{full_name}/git/trees/{default_branch}?recursive=1"
        t_res = session.get(tree_url)

        if t_res.status_code != 200:
            repo_findings.append({
                "repository": full_name,
                "default_branch": default_branch,
                "commit_sha": repo.get("default_branch_commit_sha"),
                "classification": "INCOMPLETE — ACCESS, API, OR TREE LIMITATION",
                "affected_paths": "",
                "evidence": f"HTTP {t_res.status_code} fetching git tree: {t_res.text[:100]}"
            })
            incomplete_count += 1
            checkpoint["completed_count"] += 1
            continue

        tree_json = t_res.json()
        tree_items = tree_json.get("tree", [])
        is_truncated = tree_json.get("truncated", False)

        if is_truncated:
            classification = "INCOMPLETE — ACCESS, API, OR TREE LIMITATION"
            evidence_str = "Git tree response was truncated by GitHub API (>100,000 entries or limit reached)"
            incomplete_count += 1
            repo_findings.append({
                "repository": full_name,
                "default_branch": default_branch,
                "commit_sha": repo.get("default_branch_commit_sha"),
                "classification": classification,
                "affected_paths": "",
                "evidence": evidence_str
            })
            checkpoint["completed_count"] += 1
            continue

        # Inspect tree items
        paths = [item["path"] for item in tree_items if item.get("type") == "blob"]
        
        detected_malware = []
        suspicious_items = []
        proposed_actions = []

        # 1. Check for api.js, api.json, debug_api.json
        for p in paths:
            if p in ["api.js", "api.json", "debug_api.json"] or p.endswith("/api.js") or p.endswith("/debug_api.json"):
                # Fetch content to verify
                fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/{p}?ref={default_branch}")
                if fc_res.status_code == 200:
                    raw_b64 = fc_res.json().get("content", "")
                    content_bytes = base64.b64decode(raw_b64)
                    c_sha = hashlib.sha256(content_bytes).hexdigest()
                    text = content_bytes.decode("utf-8", errors="ignore")
                    if "var z" in text or "(function boot(" in text or "splitLane(" in text or "spin(" in text or "export const api" in text or len(content_bytes) > 20000:
                        detected_malware.append((p, f"Malicious root dropper ({len(content_bytes)} bytes, SHA256: {c_sha[:12]})"))
                        proposed_actions.append({
                            "action": "DELETE",
                            "path": p,
                            "original_sha256": c_sha,
                            "size_bytes": len(content_bytes),
                            "rationale": "Confirmed second-stage JavaScript malware dropper masquerading as mock API utility"
                        })
                    else:
                        suspicious_items.append((p, f"Suspicious filename '{p}', manual review needed"))

        # 2. Check for fake fonts in fonts/ directories
        font_files = [p for p in paths if ("fonts/" in p or p.startswith("public/fonts/")) and (
            p.endswith(".ttf") or p.endswith(".woff") or p.endswith(".woff2") or p.endswith(".svg") or p.endswith(".eot") or p.endswith("README.md")
        )]
        if font_files:
            # Check if companion fa-brands-400.ttf exists
            ttf_matches = [f for f in font_files if f.endswith("fa-brands-400.ttf")]
            is_fake_font_dir = False
            for ttf_p in ttf_matches:
                fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/{ttf_p}?ref={default_branch}")
                if fc_res.status_code == 200:
                    raw_b64 = fc_res.json().get("content", "")
                    content_bytes = base64.b64decode(raw_b64)
                    c_sha = hashlib.sha256(content_bytes).hexdigest()
                    text = content_bytes.decode("utf-8", errors="ignore")
                    if c_sha == KNOWN_TTF_HASH or text.startswith("(function") or "var z" in text:
                        is_fake_font_dir = True
                        detected_malware.append((ttf_p, f"Confirmed fake font payload (JavaScript backdoor disguised as .ttf, {len(content_bytes)} bytes)"))
                        break

            if is_fake_font_dir:
                # All files in this specific fake fonts folder are malware assets
                font_dirs = set(os.path.dirname(f) for f in ttf_matches)
                for f in font_files:
                    if os.path.dirname(f) in font_dirs:
                        fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/{f}?ref={default_branch}")
                        f_sha = ""
                        f_sz = 0
                        if fc_res.status_code == 200:
                            b = base64.b64decode(fc_res.json().get("content", ""))
                            f_sha = hashlib.sha256(b).hexdigest()
                            f_sz = len(b)
                        detected_malware.append((f, f"Companion malware asset in fake font directory ({f_sz} bytes)"))
                        proposed_actions.append({
                            "action": "DELETE",
                            "path": f,
                            "original_sha256": f_sha,
                            "size_bytes": f_sz,
                            "rationale": "Malware asset belonging to fake font suite"
                        })
            else:
                for f in font_files:
                    if any(kw in f for kw in ["fa-brands", "fa-regular", "fa-solid"]):
                        suspicious_items.append((f, "FontAwesome font file in unusual directory, review needed"))

        # 3. Check .vscode/tasks.json
        if ".vscode/tasks.json" in paths:
            fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/.vscode/tasks.json?ref={default_branch}")
            if fc_res.status_code == 200:
                raw_b64 = fc_res.json().get("content", "")
                content_bytes = base64.b64decode(raw_b64)
                c_sha = hashlib.sha256(content_bytes).hexdigest()
                text = content_bytes.decode("utf-8", errors="ignore")
                try:
                    tasks_data = json.loads(text)
                    t_list = tasks_data.get("tasks", [])
                    malicious_tasks = []
                    legit_tasks = []
                    for t in t_list:
                        cmd = t.get("command", "")
                        run_on = t.get("runOptions", {}).get("runOn")
                        if "fa-brands" in cmd or run_on == "folderOpen" or "api.js" in cmd:
                            malicious_tasks.append(t)
                        else:
                            legit_tasks.append(t)
                    
                    if malicious_tasks:
                        detected_malware.append((".vscode/tasks.json", f"Silent folderOpen shell execution backdoor ({len(malicious_tasks)} malicious tasks)"))
                        if not legit_tasks:
                            proposed_actions.append({
                                "action": "DELETE",
                                "path": ".vscode/tasks.json",
                                "original_sha256": c_sha,
                                "size_bytes": len(content_bytes),
                                "rationale": "Sole purpose was malicious auto-run backdoor on folder open"
                            })
                        else:
                            # Patch tasks.json
                            tasks_data["tasks"] = legit_tasks
                            cleaned_content = json.dumps(tasks_data, indent=2) + "\n"
                            proposed_actions.append({
                                "action": "MODIFY",
                                "path": ".vscode/tasks.json",
                                "original_sha256": c_sha,
                                "new_content": cleaned_content,
                                "new_sha256": hashlib.sha256(cleaned_content.encode("utf-8")).hexdigest(),
                                "rationale": "Removed malicious auto-run task while preserving legitimate VS Code tasks"
                            })
                except Exception as e:
                    suspicious_items.append((".vscode/tasks.json", f"Parse error: {e}"))

        # 4. Check .vscode/settings.json
        if ".vscode/settings.json" in paths:
            fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/.vscode/settings.json?ref={default_branch}")
            if fc_res.status_code == 200:
                raw_b64 = fc_res.json().get("content", "")
                content_bytes = base64.b64decode(raw_b64)
                c_sha = hashlib.sha256(content_bytes).hexdigest()
                text = content_bytes.decode("utf-8", errors="ignore")
                try:
                    settings_data = json.loads(text)
                    had_malicious = False
                    if settings_data.get("task.allowAutomaticTasks") is True:
                        had_malicious = True
                        del settings_data["task.allowAutomaticTasks"]
                    if "tasks" in settings_data and settings_data["tasks"].get("runOn") == "folderOpen":
                        had_malicious = True
                        del settings_data["tasks"]
                    if settings_data.get("debug.openDebug") == "neverOpen":
                        had_malicious = True
                        del settings_data["debug.openDebug"]
                    
                    if had_malicious:
                        detected_malware.append((".vscode/settings.json", "Configured task.allowAutomaticTasks to suppress user confirmation"))
                        # Check remaining keys
                        if not settings_data:
                            proposed_actions.append({
                                "action": "DELETE",
                                "path": ".vscode/settings.json",
                                "original_sha256": c_sha,
                                "size_bytes": len(content_bytes),
                                "rationale": "Contained only malicious automatic task execution bypass settings"
                            })
                        else:
                            cleaned_content = json.dumps(settings_data, indent=2) + "\n"
                            proposed_actions.append({
                                "action": "MODIFY",
                                "path": ".vscode/settings.json",
                                "original_sha256": c_sha,
                                "new_content": cleaned_content,
                                "new_sha256": hashlib.sha256(cleaned_content.encode("utf-8")).hexdigest(),
                                "rationale": "Removed malicious auto-task permission bypass while preserving legitimate user settings"
                            })
                except Exception as e:
                    suspicious_items.append((".vscode/settings.json", f"Parse error: {e}"))

        # 5. Check package.json
        if "package.json" in paths:
            fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/package.json?ref={default_branch}")
            if fc_res.status_code == 200:
                raw_b64 = fc_res.json().get("content", "")
                content_bytes = base64.b64decode(raw_b64)
                c_sha = hashlib.sha256(content_bytes).hexdigest()
                text = content_bytes.decode("utf-8", errors="ignore")
                if "api.js" in text or "debug_api" in text:
                    try:
                        pkg_json = json.loads(text)
                        scripts = pkg_json.get("scripts", {})
                        modified = False
                        cleaned_scripts = {}
                        for s_k, s_v in scripts.items():
                            if isinstance(s_v, str) and ("api.js" in s_v or "debug_api" in s_v):
                                # Clean trigger
                                c_v = re.sub(r'\s*(&&|;|&|;)?\s*node\s+(?:\.\/)?(?:debug_)?api(?:\.js)?\s*(&&|;|&|;)?\s*', ' ', s_v, flags=re.IGNORECASE)
                                c_v = re.sub(r'^\s*(&&|;|&|;)\s*', '', c_v).strip()
                                c_v = re.sub(r'\s*(&&|;|&|;)\s*$', '', c_v).strip()
                                if c_v != s_v:
                                    cleaned_scripts[s_k] = c_v
                                    modified = True
                        if modified:
                            detected_malware.append(("package.json", f"Injected 'node api.js &&' execution trigger in scripts: {list(cleaned_scripts.keys())}"))
                            for s_k, c_v in cleaned_scripts.items():
                                pkg_json["scripts"][s_k] = c_v
                            cleaned_content = json.dumps(pkg_json, indent=2) + "\n"
                            proposed_actions.append({
                                "action": "MODIFY",
                                "path": "package.json",
                                "original_sha256": c_sha,
                                "new_content": cleaned_content,
                                "new_sha256": hashlib.sha256(cleaned_content.encode("utf-8")).hexdigest(),
                                "rationale": f"Sanitized malicious 'node api.js &&' execution triggers from scripts ({', '.join(cleaned_scripts.keys())}) while preserving all legitimate commands and dependencies"
                            })
                    except Exception as e:
                        suspicious_items.append(("package.json", f"JSON parse error: {e}"))

        # 6. Check config files (postcss.config.*, next.config.*, eslint.config.*)
        config_candidates = [p for p in paths if p in [
            "postcss.config.js", "postcss.config.mjs", "postcss.config.cjs",
            "next.config.js", "next.config.mjs", "next.config.ts",
            "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs"
        ]]
        for cfg_p in config_candidates:
            fc_res = session.get(f"https://api.github.com/repos/{full_name}/contents/{cfg_p}?ref={default_branch}")
            if fc_res.status_code == 200:
                raw_b64 = fc_res.json().get("content", "")
                content_bytes = base64.b64decode(raw_b64)
                c_sha = hashlib.sha256(content_bytes).hexdigest()
                text = content_bytes.decode("utf-8", errors="ignore")
                if "var z" in text or len(text) > 20000:
                    lines = text.split("\n")
                    cleaned_lines = []
                    found_injected_line = False
                    for line in lines:
                        if "var z" in line or (len(line) > 500 and "(function" in line):
                            found_injected_line = True
                            # Extract legitimate prefix before massive padding
                            prefix = re.split(r'\s{20,}', line)[0].strip()
                            if prefix and not prefix.startswith("var z") and not prefix.startswith("(function"):
                                cleaned_lines.append(prefix)
                        else:
                            cleaned_lines.append(line)
                    
                    if found_injected_line:
                        detected_malware.append((cfg_p, "Trailing 28KB obfuscated payload injected on export line past whitespace padding"))
                        cleaned_content = "\n".join(cleaned_lines)
                        if not cleaned_content.endswith("\n"):
                            cleaned_content += "\n"
                        # If the entire file was just malware scaffolding (e.g. createRequire + exports + payload) and no real config:
                        is_scaffold_only = "plugins" not in cleaned_content and "module.exports" not in cleaned_content and "export default" not in cleaned_content
                        if is_scaffold_only or len(cleaned_content.strip()) < 10:
                            proposed_actions.append({
                                "action": "DELETE",
                                "path": cfg_p,
                                "original_sha256": c_sha,
                                "size_bytes": len(content_bytes),
                                "rationale": "File was created solely as a malware carrier scaffolding with no legitimate user configuration"
                            })
                        else:
                            proposed_actions.append({
                                "action": "MODIFY",
                                "path": cfg_p,
                                "original_sha256": c_sha,
                                "new_content": cleaned_content,
                                "new_sha256": hashlib.sha256(cleaned_content.encode("utf-8")).hexdigest(),
                                "rationale": "Stripped trailing obfuscated payload while preserving legitimate build configuration"
                            })

        # Classification
        if detected_malware:
            classification = "CONFIRMED MALICIOUS CONTENT"
            evidence_str = "; ".join(f"{p}: {reason}" for p, reason in detected_malware)
            confirmed_count += 1
        elif suspicious_items:
            classification = "SUSPICIOUS — NEEDS MANUAL REVIEW"
            evidence_str = "; ".join(f"{p}: {reason}" for p, reason in suspicious_items)
            suspicious_count += 1
        else:
            classification = "NO KNOWN INDICATORS FOUND IN SCANNED TREE"
            evidence_str = "Full tree scanned (0 known malware indicators, 0 auto-run backdoors, 0 fake fonts)"
            clean_count += 1

        repo_findings.append({
            "repository": full_name,
            "default_branch": default_branch,
            "commit_sha": repo.get("default_branch_commit_sha"),
            "classification": classification,
            "affected_paths": "|".join(p for p, _ in (detected_malware + suspicious_items)),
            "evidence": evidence_str
        })

        if proposed_actions:
            repo_patch_dir = os.path.join(patches_dir, repo_name)
            os.makedirs(repo_patch_dir, exist_ok=True)
            for act in proposed_actions:
                act_record = {
                    "repository": full_name,
                    "default_branch": default_branch,
                    "action": act["action"],
                    "path": act["path"],
                    "original_sha256": act["original_sha256"],
                    "rationale": act["rationale"]
                }
                if act["action"] == "MODIFY":
                    # Save clean content
                    clean_file_path = os.path.join(repo_patch_dir, act["path"].replace("/", os.sep))
                    os.makedirs(os.path.dirname(clean_file_path), exist_ok=True)
                    with open(clean_file_path, "w", encoding="utf-8") as pf:
                        pf.write(act["new_content"])
                    act_record["new_sha256"] = act["new_sha256"]
                    act_record["clean_patch_file"] = os.path.relpath(clean_file_path, out_dir)
                remediation_manifest.append(act_record)

        checkpoint["completed_count"] += 1
        print(f"[{idx}/{len(personal_repos)}] {full_name}: {classification} ({len(proposed_actions)} actions)")

    # Rate limit at finish
    rl_end = session.get("https://api.github.com/rate_limit").json().get("resources", {}).get("core", {})
    checkpoint["rate_limit_final"] = rl_end.get("remaining")
    print(f"\nScan complete. Final rate limit: {rl_end.get('remaining')}/{rl_end.get('limit')}")
    print(f"Summary: Confirmed={confirmed_count}, Suspicious={suspicious_count}, Clean={clean_count}, Incomplete={incomplete_count}")

    # Write repository-findings.csv
    csv_path = os.path.join(out_dir, "repository-findings.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["repository", "default_branch", "commit_sha", "classification", "affected_paths", "evidence"])
        writer.writeheader()
        writer.writerows(repo_findings)
    print(f"Saved: {csv_path}")

    # Write remediation-manifest.json
    manifest_path = os.path.join(out_dir, "remediation-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(remediation_manifest, f, indent=2)
    print(f"Saved: {manifest_path}")

    # Write checkpoint.json
    ckpt_path = os.path.join(out_dir, "checkpoint.json")
    with open(ckpt_path, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, indent=2)
    print(f"Saved: {ckpt_path}")

    return out_dir, confirmed_count, suspicious_count, clean_count, incomplete_count, remediation_manifest

if __name__ == "__main__":
    main()
