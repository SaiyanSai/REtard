import re
import json
from pathlib import Path
from config import STATE_FILE

def extract_xml(text: str, tag: str) -> str:
    match = re.search(rf'<{tag}>(.*?)</{tag}>', text, re.DOTALL)
    return match.group(1).strip() if match else ""

def check_if_wrapper(name: str, body: str) -> bool:
    if not name.startswith("FUN_"): return False
    lines = [l.strip() for l in body.split('\n') if l.strip() and l not in ['{', '}'] and not l.startswith(('/', '*'))]
    if len(lines) > 12: return False
    calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', body)
    for target in calls:
        if not target.startswith("FUN_") and target not in ["if", "while", "for", "switch", "return"]:
            return True
    return False

def save_json_state(state):
    data = {"functions": state["functions"], "symbol_table": state["symbol_table"]}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_json_state():
    if Path(STATE_FILE).exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"functions": {}, "symbol_table": {}}