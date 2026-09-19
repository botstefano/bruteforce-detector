import subprocess, sys, json, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
r = subprocess.run(
    [sys.executable, "-m", "pip", "install", "--dry-run", "--quiet",
     "--report", "pip_report.json", "-r", "requirements.txt"],
    capture_output=True, text=True
)
if r.returncode != 0:
    print("PIP FALLO (stderr):", r.stderr)
    sys.exit(r.returncode)
with open("pip_report.json", encoding="utf-8") as f:
    report = json.load(f)
print(f"TOTAL paquetes resueltos: {len(report['install'])}")
print("-" * 55)
for x in report["install"]:
    m = x["metadata"]
    print(f"  {m['name']:<26} {m['version']}")
print("-" * 55)
print("TODAS las versiones existen en PyPI y sub-dependencias se resuelven OK")
os.remove("pip_report.json")
