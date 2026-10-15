import re
import json
import base64
import subprocess
import requests

def get_token():
    return subprocess.check_output(["gh", "auth", "token"]).decode().strip()

token = get_token()
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

# Fetch api.js from backend-one
res_api = requests.get("https://api.github.com/repos/AforArdi/backend-one/contents/api.js", headers=headers)
content_api = base64.b64decode(res_api.json()["content"]).decode("utf-8", errors="ignore")

# Fetch fa-brands-400.ttf from backend-one
res_ttf = requests.get("https://api.github.com/repos/AforArdi/backend-one/contents/prisma/migrations/20260809094103_init/public/fonts/fa-brands-400.ttf", headers=headers)
content_ttf = base64.b64decode(res_ttf.json()["content"]).decode("utf-8", errors="ignore")

# Fetch postcss.config.mjs from dragon-news-nextjs
res_pc = requests.get("https://api.github.com/repos/AforArdi/dragon-news-nextjs/contents/postcss.config.mjs", headers=headers)
content_pc = base64.b64decode(res_pc.json()["content"]).decode("utf-8", errors="ignore")

print(f"api.js length: {len(content_api)}")
print(f"fa-brands-400.ttf length: {len(content_ttf)}")
print(f"postcss.config.mjs length: {len(content_pc)}")

# Extract string arrays from the obfuscated code
# Often JS obfuscators have an array of hex strings at the beginning, e.g. ['hex1', 'hex2']
def extract_hex_strings(text):
    hex_strs = re.findall(r"'([0-9a-fA-F]{4,})'", text)
    # decode hex if printable
    decoded = []
    for h in hex_strs:
        try:
            b = bytes.fromhex(h)
            d = b.decode("utf-8", errors="ignore")
            if len(d) > 3 and any(c.isalnum() for c in d):
                decoded.append((h, d))
        except Exception:
            pass
    return decoded

print("\n--- Hex strings decoded from api.js ---")
api_hex = extract_hex_strings(content_api)
for h, d in api_hex[:30]:
    print(f"  {h} -> {repr(d)}")

print("\n--- Hex strings decoded from fa-brands-400.ttf ---")
ttf_hex = extract_hex_strings(content_ttf)
for h, d in ttf_hex[:30]:
    print(f"  {h} -> {repr(d)}")

# Check for URL or IP patterns
for label, txt in [("api.js", content_api), ("fa-brands-400.ttf", content_ttf), ("postcss.config.mjs", content_pc)]:
    print(f"\n--- Regex matches in {label} ---")
    urls = re.findall(r'https?://[^\s\'"]+', txt)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', txt)
    cmds = re.findall(r'(child_process|exec|spawn|eval|Function|Buffer|base64|socket|connect|http|https|net|crypto)', txt)
    print(f"  URLs: {urls}")
    print(f"  IPs: {ips}")
    print(f"  Keywords: {set(cmds)}")
