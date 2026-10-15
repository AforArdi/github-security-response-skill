import subprocess
import requests
import base64
import re
import hashlib

t = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
h = {"Authorization": f"Bearer {t}"}

# Fetch api.js
r_api = requests.get("https://api.github.com/repos/AforArdi/backend-one/contents/api.js", headers=h)
c_api = base64.b64decode(r_api.json()["content"]).decode("utf-8", errors="ignore")

# Fetch postcss.config.mjs
r_pc = requests.get("https://api.github.com/repos/AforArdi/dragon-news-nextjs/contents/postcss.config.mjs", headers=h)
c_pc = base64.b64decode(r_pc.json()["content"]).decode("utf-8", errors="ignore")

# Extract the injected block from postcss.config.mjs
line = [l for l in c_pc.split("\n") if "var z" in l][0]
prefix = line.split("var z")[0].strip()
injected_payload = "var z" + line.split("var z")[1]

print(f"Legitimate prefix in postcss.config.mjs: {repr(prefix)}")
print(f"Injected payload length: {len(injected_payload)}")
print(f"Injected payload SHA256: {hashlib.sha256(injected_payload.encode('utf-8')).hexdigest()}")

# Compare with api.js injected payload
line_api = [l for l in c_api.split("\n") if "var z" in l][0]
injected_api = "var z" + line_api.split("var z")[1]
print(f"Injected in api.js length: {len(injected_api)}")
print(f"Injected in api.js SHA256: {hashlib.sha256(injected_api.encode('utf-8')).hexdigest()}")
print(f"Are injected payloads in api.js and postcss.config.mjs identical? {injected_payload == injected_api}")

# Compare with fa-brands-400.ttf
r_ttf = requests.get("https://api.github.com/repos/AforArdi/backend-one/contents/prisma/migrations/20260809094103_init/public/fonts/fa-brands-400.ttf", headers=h)
c_ttf = base64.b64decode(r_ttf.json()["content"]).decode("utf-8", errors="ignore")
print(f"fa-brands-400.ttf length: {len(c_ttf)}")
print(f"fa-brands-400.ttf SHA256: {hashlib.sha256(c_ttf.encode('utf-8')).hexdigest()}")
print(f"Does fa-brands-400.ttf contain 'var z'? {'var z' in c_ttf}")
