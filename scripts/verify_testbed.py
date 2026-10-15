"""
Testbed Diagnostics & Verification Script for SentraIPS.
Inspects container states, charon daemons, IP routing, and responder health.
"""

from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_cmd(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def check():
    print("=================================================================")
    print("  SentraIPS Testbed Diagnostics")
    print("=================================================================")

    # 1. Docker check
    code, stdout, _ = run_cmd(["docker", "--version"])
    print(f"Docker Engine      : {'OK - ' + stdout if code == 0 else 'NOT FOUND'}")

    # 2. Containers check
    code, stdout, _ = run_cmd(["docker", "ps", "--format", "{{.Names}}: {{.Status}}"])
    print(f"\nRunning Containers:\n{stdout if stdout else '  No containers running'}")

    # 3. strongSwan status on Gateway A
    print("\n--- Gateway A (Moon) Status ---")
    code, stdout, stderr = run_cmd(["docker", "exec", "ipsec-gateway-a", "ipsec", "status"])
    if code == 0:
        print(stdout)
    else:
        print(f"Failed to query strongSwan: {stderr}")

    # 4. strongSwan status on Gateway B
    print("\n--- Gateway B (Sun) Status ---")
    code, stdout, stderr = run_cmd(["docker", "exec", "ipsec-gateway-b", "ipsec", "status"])
    if code == 0:
        print(stdout)
    else:
        print(f"Failed to query strongSwan: {stderr}")

    # 5. Gateway B Responder Service Check
    print("\n--- Gateway B Responder Check ---")
    code, stdout, stderr = run_cmd(["docker", "exec", "ipsec-gateway-b", "curl", "-s", "http://127.0.0.1:8080/status"])
    if code == 0 and "ok" in stdout:
        print(f"HTTP Responder     : OK ({stdout})")
    else:
        print(f"HTTP Responder     : FAILED ({stderr or stdout})")

    print("=================================================================")


if __name__ == "__main__":
    check()
