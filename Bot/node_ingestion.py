import re
from pathlib import Path
from state import REState
from utils import load_json_state, check_if_wrapper
from config import TARGET_BINARY, OUTPUT_C
from decompile import decompile_binary

def ingestion_node(state: REState):
    print("\n" + "="*30 + "\n[PHASE: INGESTION]\n" + "="*30)
    
    if not Path(OUTPUT_C).exists():
        decompile_binary(TARGET_BINARY, OUTPUT_C)

    prev = load_json_state()
    functions = prev.get("functions", {})
    symbol_table = prev.get("symbol_table", {})
    
    with open(OUTPUT_C, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"// --- Function: (FUN_.*?) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
    matches = re.findall(pattern, content, re.DOTALL)

    for name, addr, body in matches:
        if name not in functions:
            body_text = body.strip()
            functions[name] = {
                "address": addr, "body": body_text,
                "status": "PENDING", "string_score": -1,
                "is_wrapper": check_if_wrapper(name, body_text),
                "summary": ""
            }
    return {"functions": functions, "symbol_table": symbol_table, "phase": "triage", "history": [f"Ingested {len(functions)} functions."]}