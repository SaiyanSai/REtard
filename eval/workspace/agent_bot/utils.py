import re
import json
import shutil
from pathlib import Path
from config import STATE_FILE, OUTPUT_C

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

def update_c_file(state):
    clean_c = Path(OUTPUT_C).with_suffix('.clean.c')
    out_c = Path(OUTPUT_C)

    if not clean_c.exists() and out_c.exists():
        shutil.copy(out_c, clean_c)
        
    if not clean_c.exists():
        return

    with open(clean_c, "r", encoding="utf-8") as f:
        content = f.read()

    for orig_func_name, func_data in state.get("functions", {}).items():
        summary = func_data.get("summary", "").strip()
        if summary:
            comment = f"\n/*\n * === AI ANALYSIS SUMMARY ===\n"
            for line in summary.split('\n'):
                comment += f" * {line}\n"
            comment += " */\n"
            pattern = rf'^([^\n]*\b{re.escape(orig_func_name)}\b\s*\()'
            content = re.sub(pattern, lambda m: comment + m.group(1), content, count=1, flags=re.MULTILINE)

    sorted_symbols = sorted(state.get("symbol_table", {}).items(), key=lambda x: len(x[0]), reverse=True)
    for old_sym, new_sym in sorted_symbols:
        content = re.sub(rf'\b{re.escape(old_sym)}\b', new_sym, content)

    with open(out_c, "w", encoding="utf-8") as f:
        f.write(content)

def save_json_state(state):
    data = {"functions": state.get("functions", {}), "symbol_table": state.get("symbol_table", {})}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    update_c_file(state)

def load_json_state():
    if Path(STATE_FILE).exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"functions": {}, "symbol_table": {}}