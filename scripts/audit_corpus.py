import json
from pathlib import Path

BASE = Path("/mnt/c/Users/halsa/Desktop/GP/GP2/data/corpus")

for fname in sorted(BASE.glob("*.json")):
    d = json.loads(fname.read_text())
    controls = d.get("controls", [])
    fw = d.get("framework", {})
    print(f"{fw.get('name','?')} ({fw.get('version','?')}): {len(controls)} controls")
