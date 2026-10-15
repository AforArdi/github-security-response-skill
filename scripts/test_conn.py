import subprocess
import requests

token = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

res = requests.get("https://api.github.com/user", headers=headers)
print("Status:", res.status_code, "User:", res.json().get("login"))
