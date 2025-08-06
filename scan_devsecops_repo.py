#!/usr/bin/env python3

import os
import re
import subprocess
from datetime import datetime

# Path to your GitHub repo
REPO_PATH = os.path.expanduser("~/projects/repos/devsecops-lab")

# Output log file (timestamped)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
REPORT_FILE = os.path.expanduser(f"~/scan_results_{timestamp}.txt")

# Define patterns for common secrets
CREDENTIAL_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key.*?[=:]\s*[0-9a-zA-Z/+]{40}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "Generic API Key": r"(?i)(api[_-]?key|token)[\s:=]+['\"]?[a-z0-9_\-]{16,45}['\"]?",
    "Username/Password in URL": r"https?:\/\/[^\/\s]+:[^\/\s]+@",
}

def log(msg):
    print(msg)
    with open(REPORT_FILE, "a") as f:
        f.write(msg + "\n")

def scan_git_repo(path):
    log(f"🔍 Scanning Git repository at: {path}")
    log(f"📄 Output log: {REPORT_FILE}\n")

    # Check if it's a valid Git repo
    try:
        output = subprocess.check_output(["git", "-C", path, "ls-files"], universal_newlines=True)
    except subprocess.CalledProcessError:
        log("❌ Not a valid git repository.")
        return

    found = False
    files = output.splitlines()
    for file in files:
        full_path = os.path.join(path, file)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            log(f"⚠️ Could not read {file}: {e}")
            continue

        for name, pattern in CREDENTIAL_PATTERNS.items():
            if re.search(pattern, content):
                log(f"[!] Possible {name} found in {file}")
                found = True

    if not found:
        log("✅ Scan complete. No secrets detected.")

if __name__ == "__main__":
    scan_git_repo(REPO_PATH)

import sys
# ...
	if not found:
	  log("✅ Scan complete. No secrets detected.")
	  sys.exit(0)
	else:
	  log("❌ Potential secrest found! Failing scan.")
	  sys.exit(1)
